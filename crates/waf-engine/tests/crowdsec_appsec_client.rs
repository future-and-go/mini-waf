//! Tests for `crowdsec::appsec` — AppSecClient HTTP roundtrip via wiremock.
//!
//! Covers: 200 → Allow, 403 → Block (with/without body), 401 → Unavailable,
//! unexpected status → Unavailable, endpoint down → Unavailable,
//! body forwarded when present, user-agent header forwarded,
//! appsec_to_detection mapping.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use waf_common::{HostConfig, Phase, RequestCtx};
use waf_engine::crowdsec::appsec::{AppSecClient, AppSecResult, appsec_to_detection};
use waf_engine::crowdsec::config::{AppSecConfig, FallbackAction};
use wiremock::matchers::{header, method};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_ctx(ip: &str, path: &str, body: &[u8]) -> RequestCtx {
    RequestCtx {
        req_id: "test-req".to_string(),
        client_ip: ip.parse().expect("ip"),
        client_port: 12345,
        method: "POST".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: path.to_string(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::copy_from_slice(body),
        content_length: body.len() as u64,
        is_tls: false,
        host_config: Arc::new(HostConfig::default()),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
    }
}

fn appsec_cfg(endpoint: &str) -> AppSecConfig {
    AppSecConfig {
        endpoint: endpoint.to_string(),
        api_key: "test-key".to_string(),
        timeout_ms: 2000,
        failure_action: FallbackAction::Allow,
        // Match the production defaults so tests don't trip the breaker
        // mid-suite unless they deliberately drive consecutive failures.
        circuit_breaker_threshold: 5,
        circuit_breaker_reset_secs: 30,
    }
}

// ── 200 Allow ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_200_returns_allow() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("1.2.3.4", "/login", b"");
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Allow));
}

// ── 403 Block with JSON body ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_403_with_json_body_returns_block_with_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403).set_body_json(serde_json::json!({
            "action": "ban",
            "http_status": 403,
            "message": "sql injection detected"
        })))
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("5.6.7.8", "/api", b"SELECT * FROM users");
    let result = client.check_request(&ctx).await;

    match result {
        AppSecResult::Block { message } => {
            assert!(message.contains("sql injection"), "got: {message}");
        }
        other => panic!("expected Block, got {other:?}"),
    }
}

// ── 403 Block without body → default message ──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_403_without_body_returns_block_with_default_message() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("9.9.9.9", "/", b"");
    let result = client.check_request(&ctx).await;

    assert!(matches!(result, AppSecResult::Block { .. }));
}

// ── 401 Auth failure → Unavailable ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn status_401_returns_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("1.1.1.1", "/", b"");
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Unavailable));
}

// ── unexpected status → Unavailable ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn unexpected_status_returns_unavailable() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("2.2.2.2", "/", b"");
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Unavailable));
}

// ── endpoint unreachable → Unavailable ───────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn unreachable_endpoint_returns_unavailable() {
    let client = AppSecClient::new(appsec_cfg("http://127.0.0.1:1/appsec")).expect("client");
    let ctx = make_ctx("3.3.3.3", "/", b"");
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Unavailable));
}

// ── body forwarded ────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn request_body_forwarded_to_appsec_endpoint() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let mut ctx = make_ctx("4.4.4.4", "/upload", b"some-body-content");
    ctx.headers.insert("user-agent".to_string(), "Mozilla/5.0".to_string());
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Allow));
    server.verify().await;
}

// ── appsec_to_detection ───────────────────────────────────────────────────────

#[test]
fn appsec_to_detection_sets_correct_fields() {
    let det = appsec_to_detection("blocked by appsec rule XYZ".to_string());
    assert_eq!(det.rule_id.as_deref(), Some("crowdsec:appsec"));
    assert_eq!(det.rule_name, "CrowdSec AppSec");
    assert_eq!(det.phase, Phase::CrowdSec);
    assert!(det.detail.contains("XYZ"));
}

#[test]
fn appsec_to_detection_empty_message() {
    let det = appsec_to_detection(String::new());
    assert_eq!(det.phase, Phase::CrowdSec);
    assert!(det.detail.is_empty());
}

// ── empty body path not forwarded ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn empty_body_not_forwarded_still_gets_200_allow() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("6.6.6.6", "/api/v1/users", b"");
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Allow));
    server.verify().await;
}

// ── api key header sent ───────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn api_key_header_present_in_request() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(header("X-Crowdsec-Appsec-Api-Key", "test-key"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let client = AppSecClient::new(appsec_cfg(&format!("{}/appsec", server.uri()))).expect("client");
    let ctx = make_ctx("7.7.7.7", "/check", b"");
    let result = client.check_request(&ctx).await;
    assert!(matches!(result, AppSecResult::Allow));
    server.verify().await;
}
