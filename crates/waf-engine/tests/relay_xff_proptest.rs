//! FR-007 phase-07 — proptest fuzz over arbitrary XFF headers.
//!
//! Invariants under test:
//! 1. `evaluate` never panics for any input.
//! 2. `real_ip` is either `peer_ip` or is contained in the parsed chain entries.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::redundant_clone,
    clippy::collapsible_else_if
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::{HeaderMap, HeaderName, HeaderValue};
use proptest::prelude::*;
use waf_engine::relay::providers::parse::parse_xff_chain;
use waf_engine::relay::{ProviderRegistry, RelayConfig, RelayDetector};

// ─── IP strategies ──────────────────────────────────────────────────────────

fn arb_ipv4() -> impl Strategy<Value = Ipv4Addr> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

fn arb_ipv6() -> impl Strategy<Value = Ipv6Addr> {
    (
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
        any::<u16>(),
    )
        .prop_map(|(a, b, c, d, e, f, g, h)| Ipv6Addr::new(a, b, c, d, e, f, g, h))
}

fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![arb_ipv4().prop_map(IpAddr::V4), arb_ipv6().prop_map(IpAddr::V6),]
}

/// Build one XFF token with optional decorations (brackets, port, zone-id).
fn arb_xff_token(ip: IpAddr) -> impl Strategy<Value = String> {
    let s = ip.to_string();
    let is_v6 = ip.is_ipv6();
    let s0 = s.clone();
    let s1 = s.clone();
    let s2 = s.clone();
    let s3 = s.clone();
    let s4 = s.clone();
    prop_oneof![
        // Bare IP string.
        Just(s0),
        // IPv4 with optional :port decoration.
        if is_v6 {
            Just(s1).boxed()
        } else {
            (0u16..=65535u16).prop_map(move |p| format!("{s1}:{p}")).boxed()
        },
        // IPv6 with brackets and optional port.
        if is_v6 {
            (0u16..=65535u16).prop_map(move |p| format!("[{s2}]:{p}")).boxed()
        } else {
            Just(s2).boxed()
        },
        // IPv6 with zone-id (stripped by parser).
        if is_v6 {
            Just(format!("{s3}%eth0")).boxed()
        } else {
            Just(s4).boxed()
        },
    ]
}

/// Build an arbitrary XFF header value with 0..=40 entries.
fn arb_xff_chain_str() -> impl Strategy<Value = String> {
    prop::collection::vec(arb_ip(), 0..=40).prop_flat_map(|ips| {
        let token_strats: Vec<_> = ips.into_iter().map(arb_xff_token).collect();
        token_strats.prop_map(|tokens| tokens.join(", "))
    })
}

fn make_detector() -> RelayDetector {
    let yaml = r#"
relay_detection:
  trusted_proxies: []
  max_chain_depth: 32
  signals:
    enabled: ["xff_validator", "proxy_chain"]
"#;
    let cfg = RelayConfig::from_yaml_str(yaml).unwrap();
    let registry = ProviderRegistry::from_config(&cfg).unwrap();
    RelayDetector::new(cfg, registry)
}

fn xff_header_name() -> HeaderName {
    HeaderName::from_static("x-forwarded-for")
}

// ─── proptest suite ──────────────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig {
        // Disable on-disk failure-persistence file (would otherwise leak into the
        // repo on first failure). For a fully reproducible CI run, set the
        // `PROPTEST_RNG_SEED` env var to any fixed value — proptest uses it to
        // seed the runner deterministically.
        failure_persistence: None,
        cases: 256,
        ..Default::default()
    })]

    /// Invariant 1: evaluate never panics.
    /// Invariant 2: real_ip is peer_ip OR present in the parsed XFF chain.
    #[test]
    fn evaluate_invariants(
        chain_str in arb_xff_chain_str(),
        peer in arb_ip(),
    ) {
        let det = make_detector();
        let mut headers = HeaderMap::new();
        if !chain_str.is_empty() && let Ok(hv) = HeaderValue::from_str(&chain_str) {
            headers.append(xff_header_name(), hv);
        }

        // Invariant 1: must not panic.
        let id = det.evaluate(peer, &headers);

        // Invariant 2: real_ip ∈ {peer} ∪ parsed_chain.
        let parsed = parse_xff_chain(&headers, &[xff_header_name()]);
        let chain_contains_real = parsed.entries.contains(&id.real_ip);
        let is_peer = id.real_ip == peer;
        prop_assert!(
            is_peer || chain_contains_real,
            "real_ip={} not in peer={} or chain={:?}",
            id.real_ip,
            peer,
            parsed.entries
        );
    }

    /// Extra: evaluating with an empty header map always returns peer as real_ip.
    #[test]
    fn empty_headers_real_ip_is_peer(peer in arb_ip()) {
        let det = make_detector();
        let id = det.evaluate(peer, &HeaderMap::new());
        prop_assert_eq!(id.real_ip, peer);
    }
}
