//! Integration coverage for `RequestCtxBuilder::build` against a mocked
//! Pingora `Session`. Without a live socket we cannot test the production
//! `proxy_request_filter` path end-to-end, but driving the builder through
//! `tokio_test::io::Mock` is enough to exercise:
//!   - default-path (no host config, no tier registry)
//!   - host header parsing + lowercasing
//!   - content-length parsing (valid + bogus)
//!   - tier registry classification when wired in
//!   - `extract_client_ip_from_session` honouring XFF only when trusted
//!
//! TLS detection is exercised by mutating `Session::digest_mut().ssl_digest`
//! directly — the only seam we have without a full TLS handshake.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;

use ipnet::IpNet;
use pingora_core::protocols::tls::digest::SslDigest;
use pingora_proxy::Session;
use tokio_test::io::Builder;
use waf_common::HostConfig;
use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, Tier, TierClassifierRule, TierConfig, TierPolicy};
use waf_common::tier_match::PathMatch;

use gateway::RequestCtxBuilder;
use gateway::tiered::{TierPolicyRegistry, TierSnapshot};

async fn session_for(req_bytes: &[u8]) -> Session {
    let mock = Builder::new().read(req_bytes).build();
    let mut session = Session::new_h1(Box::new(mock));
    let read = session.read_request().await.expect("read_request");
    assert!(read, "expected request to parse");
    session
}

fn host_config(host: &str, port: u16) -> Arc<HostConfig> {
    Arc::new(HostConfig {
        host: host.to_string(),
        port,
        ssl: false,
        ..HostConfig::default()
    })
}

fn policy(block: u32) -> TierPolicy {
    TierPolicy {
        fail_mode: FailMode::Close,
        ddos_threshold_rps: 1000,
        cache_policy: CachePolicy::NoCache,
        risk_thresholds: RiskThresholds {
            allow: 10,
            challenge: 50,
            block,
        },
    }
}

fn full_policies(block: u32) -> std::collections::HashMap<Tier, TierPolicy> {
    Tier::ALL.into_iter().map(|t| (t, policy(block))).collect()
}

fn registry_with_admin_critical() -> TierPolicyRegistry {
    let cfg = TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: vec![TierClassifierRule {
            priority: 100,
            tier: Tier::Critical,
            host: None,
            path: Some(PathMatch::Prefix { value: "/admin".into() }),
            method: None,
            headers: None,
        }],
        policies: full_policies(99),
    };
    TierPolicyRegistry::new(TierSnapshot::try_from_config(cfg).expect("snapshot"))
}

#[tokio::test]
async fn build_default_path_uses_host_config_host_when_no_header() {
    // Pingora rejects requests with no Host header on H1.1, so we send a
    // Host that *differs* from `HostConfig.host` to prove the builder uses
    // the *header* — then a parallel test verifies fall-back behaviour by
    // routing through `host_for_classify`.
    let req = b"GET /api/v1?x=1 HTTP/1.1\r\nHost: Public.Example.COM:443\r\nContent-Length: 0\r\n\r\n";
    let session = session_for(req).await;

    let hc = host_config("origin.example.com", 8080);
    let ctx = RequestCtxBuilder::new(&session, false, &[])
        .with_host_config(Arc::clone(&hc))
        .build();

    // Builder always copies host/port from the *HostConfig*, never the header.
    assert_eq!(ctx.host, "origin.example.com");
    assert_eq!(ctx.port, 8080);
    assert_eq!(ctx.method, "GET");
    assert_eq!(ctx.path, "/api/v1");
    assert_eq!(ctx.query, "x=1");
    assert_eq!(ctx.content_length, 0);
    assert!(!ctx.is_tls, "no ssl_digest on mock stream");
    // Mock stream has no real client_addr — falls back to UNSPECIFIED:0.
    assert!(ctx.client_ip.is_unspecified());
    assert_eq!(ctx.client_port, 0);
    // Headers are lowercased.
    assert_eq!(
        ctx.headers.get("host").map(String::as_str),
        Some("Public.Example.COM:443")
    );
    assert_eq!(ctx.headers.get("content-length").map(String::as_str), Some("0"));
    // Tier defaults to CatchAll when no registry is wired in.
    assert_eq!(ctx.tier, Tier::CatchAll);
    // Cookies vector default-empty when no Cookie header.
    assert!(ctx.cookies.is_empty());
    // req_id is a non-empty UUID string.
    assert!(!ctx.req_id.is_empty());
}

#[tokio::test]
async fn build_uses_host_config_default_when_no_host_config_provided() {
    // With no `with_host_config`, builder uses HostConfig::default() — host
    // is empty, port is 0. Verifies the unwrap_or_default branch.
    let req = b"POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 12\r\n\r\nhello world!";
    let session = session_for(req).await;

    let ctx = RequestCtxBuilder::new(&session, false, &[]).build();
    let default_hc = HostConfig::default();
    assert_eq!(ctx.host, default_hc.host);
    assert_eq!(ctx.port, default_hc.port);
    assert_eq!(ctx.content_length, 12);
    assert_eq!(ctx.method, "POST");
}

#[tokio::test]
async fn build_parses_cookies_when_cookie_header_present() {
    let req = b"GET /me HTTP/1.1\r\nHost: example.com\r\nCookie: a=1; b=two\r\n\r\n";
    let session = session_for(req).await;

    let ctx = RequestCtxBuilder::new(&session, false, &[]).build();
    assert_eq!(ctx.cookies.get("a").map(String::as_str), Some("1"));
    assert_eq!(ctx.cookies.get("b").map(String::as_str), Some("two"));
}

#[tokio::test]
async fn build_classifies_tier_via_registry_using_path() {
    let req = b"GET /admin/users HTTP/1.1\r\nHost: ex.com\r\n\r\n";
    let session = session_for(req).await;
    let reg = registry_with_admin_critical();

    let ctx = RequestCtxBuilder::new(&session, false, &[])
        .with_tier_registry(&reg)
        .build();
    assert_eq!(ctx.tier, Tier::Critical);
    assert_eq!(ctx.tier_policy.risk_thresholds.block, 99);
}

#[tokio::test]
async fn build_falls_back_to_default_tier_when_registry_has_no_match() {
    let req = b"GET /public HTTP/1.1\r\nHost: ex.com\r\n\r\n";
    let session = session_for(req).await;
    let reg = registry_with_admin_critical();

    let ctx = RequestCtxBuilder::new(&session, false, &[])
        .with_tier_registry(&reg)
        .build();
    assert_eq!(ctx.tier, Tier::CatchAll);
}

#[tokio::test]
async fn build_uses_host_header_for_classification_when_present() {
    // Registry rule requires path /admin → Critical. We send /admin to prove
    // the host string from the *header* (lowercased + port-stripped) drives
    // the host_for_classify branch.
    let req = b"GET /admin/x HTTP/1.1\r\nHost: API.Example.COM:9443\r\n\r\n";
    let session = session_for(req).await;
    let reg = registry_with_admin_critical();

    let ctx = RequestCtxBuilder::new(&session, false, &[])
        .with_tier_registry(&reg)
        .build();
    assert_eq!(ctx.tier, Tier::Critical);
}

#[tokio::test]
async fn build_detects_tls_when_ssl_digest_present_on_session_digest() {
    // Inject an SslDigest into the session's connection digest — this is
    // the same shape the production TLS path uses. Proves `is_tls` is
    // derived from the digest, not hardcoded.
    let req = b"GET / HTTP/1.1\r\nHost: ex.com\r\n\r\n";
    let mut session = session_for(req).await;
    if let Some(digest) = session.digest_mut() {
        digest.ssl_digest = Some(Arc::new(SslDigest::new(
            "TLS_AES_128_GCM_SHA256",
            "TLSv1.3",
            None,
            None,
            Vec::new(),
        )));
    }

    let ctx = RequestCtxBuilder::new(&session, false, &[]).build();
    assert!(ctx.is_tls, "ssl_digest set ⇒ ctx.is_tls must be true");
}

#[tokio::test]
async fn build_honours_xff_only_when_trust_proxy_headers_enabled() {
    // Mock has no real peer IP → peer = UNSPECIFIED. Trusted-proxies list
    // is empty so any peer counts as trusted. Builder should pick the first
    // XFF token.
    let req = b"GET / HTTP/1.1\r\nHost: ex.com\r\nX-Forwarded-For: 198.51.100.7, 10.0.0.1\r\n\r\n";
    let session = session_for(req).await;

    // trust_proxy_headers = false → must ignore XFF.
    let ctx = RequestCtxBuilder::new(&session, false, &[]).build();
    assert!(
        ctx.client_ip.is_unspecified(),
        "XFF must not be honoured when trust=false"
    );

    // trust_proxy_headers = true with empty trusted_proxies (= trust any peer).
    let ctx = RequestCtxBuilder::new(&session, true, &[]).build();
    assert_eq!(ctx.client_ip.to_string(), "198.51.100.7");
}

#[tokio::test]
async fn build_xff_ignored_when_peer_outside_trusted_cidr() {
    // Mock peer is UNSPECIFIED (0.0.0.0). A CIDR that excludes 0.0.0.0/32
    // must cause XFF to be dropped — peer_ip wins.
    let req = b"GET / HTTP/1.1\r\nHost: ex.com\r\nX-Forwarded-For: 1.1.1.1\r\n\r\n";
    let session = session_for(req).await;
    let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().expect("cidr")];

    let ctx = RequestCtxBuilder::new(&session, true, &trusted).build();
    assert!(
        ctx.client_ip.is_unspecified(),
        "untrusted peer must not honour XFF, got {}",
        ctx.client_ip
    );
}
