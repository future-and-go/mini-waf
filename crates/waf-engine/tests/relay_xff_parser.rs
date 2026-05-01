//! FR-007 phase-07 — XFF parser table-driven integration tests.
//!
//! Exercises `parse_xff_chain` and the XFF signal path via `RelayDetector`
//! + `XffValidator`. Complements the unit tests in `providers/parse.rs` with
//! end-to-end coverage through the provider registry.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::doc_lazy_continuation
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use http::{HeaderMap, HeaderName, HeaderValue};
use waf_engine::relay::providers::XffValidator;
use waf_engine::relay::providers::parse::{MAX_CHAIN_ENTRIES, MAX_HEADER_BYTES, ParsedChain, parse_xff_chain};
use waf_engine::relay::signal::{RelayCtx, Signal, SignalProvider};
use waf_engine::relay::{ClientIdentity, ProviderRegistry, RelayConfig, RelayDetector};

// ─── helpers ────────────────────────────────────────────────────────────────

fn xff_name() -> HeaderName {
    HeaderName::from_static("x-forwarded-for")
}

fn xri_name() -> HeaderName {
    HeaderName::from_static("x-real-ip")
}

fn hdr_single(name: HeaderName, value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.append(name, HeaderValue::from_str(value).unwrap());
    h
}

fn hdr_multi(entries: &[(&str, &str)]) -> HeaderMap {
    let mut h = HeaderMap::new();
    for (name, val) in entries {
        h.append(
            HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(val).unwrap(),
        );
    }
    h
}

fn xff_validator(trusted: &[&str]) -> XffValidator {
    let names = vec!["X-Forwarded-For".to_string()];
    let cidrs: Vec<ipnet::IpNet> = trusted.iter().map(|s| s.parse().unwrap()).collect();
    XffValidator::new(&names, cidrs).unwrap()
}

fn make_detector_with_xff() -> RelayDetector {
    let yaml = r#"
relay_detection:
  trusted_proxies: []
  max_chain_depth: 10
  signals:
    enabled: ["xff_validator"]
"#;
    let cfg = RelayConfig::from_yaml_str(yaml).unwrap();
    let registry = ProviderRegistry::from_config(&cfg).unwrap();
    RelayDetector::new(cfg, registry)
}

// ─── parse_xff_chain unit-style table tests ──────────────────────────────────

#[test]
fn empty_header_yields_empty_chain() {
    let p = parse_xff_chain(&HeaderMap::new(), &[xff_name()]);
    assert!(p.entries.is_empty());
    assert!(!p.has_error());
}

#[test]
fn single_ipv4() {
    let p = parse_xff_chain(&hdr_single(xff_name(), "1.2.3.4"), &[xff_name()]);
    assert_eq!(p.entries, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    assert!(!p.has_error());
}

#[test]
fn ipv6_bracketed_with_port() {
    let p = parse_xff_chain(&hdr_single(xff_name(), "[2001:db8::1]:443"), &[xff_name()]);
    let expected: IpAddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into();
    assert_eq!(p.entries, vec![expected]);
    assert!(!p.has_error());
}

#[test]
fn ipv6_zone_id_stripped() {
    let p = parse_xff_chain(&hdr_single(xff_name(), "fe80::1%eth0"), &[xff_name()]);
    let expected: IpAddr = "fe80::1".parse::<Ipv6Addr>().unwrap().into();
    assert_eq!(p.entries, vec![expected]);
    assert!(!p.has_error());
}

#[test]
fn ipv4_with_port_stripped() {
    let p = parse_xff_chain(&hdr_single(xff_name(), "1.2.3.4:8080"), &[xff_name()]);
    let expected: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
    assert_eq!(p.entries, vec![expected]);
    assert!(!p.has_error());
}

#[test]
fn malformed_token_flags_xff_malformed() {
    let p = parse_xff_chain(&hdr_single(xff_name(), "not-an-ip"), &[xff_name()]);
    assert!(p.malformed);
    assert!(p.entries.is_empty());
}

#[test]
fn folded_headers_concatenated() {
    let h = hdr_multi(&[("x-forwarded-for", "1.1.1.1"), ("x-forwarded-for", "2.2.2.2, 3.3.3.3")]);
    let p = parse_xff_chain(&h, &[xff_name()]);
    assert_eq!(p.entries.len(), 3);
    assert!(!p.has_error());
}

#[test]
fn byte_cap_exceeded_returns_too_long_bytes() {
    let big = "1".repeat(MAX_HEADER_BYTES + 10);
    let p = parse_xff_chain(&hdr_single(xff_name(), &big), &[xff_name()]);
    assert!(p.too_long_bytes);
    assert!(p.entries.is_empty());
}

#[test]
fn count_cap_exceeded_returns_too_long_count() {
    // Build a chain with more than MAX_CHAIN_ENTRIES (32) entries.
    let many: Vec<String> = (0..=MAX_CHAIN_ENTRIES).map(|i| format!("10.0.0.{}", i % 256)).collect();
    let joined = many.join(", ");
    let p = parse_xff_chain(&hdr_single(xff_name(), &joined), &[xff_name()]);
    assert!(p.too_long_count);
    assert!(p.entries.is_empty());
}

// ─── end-to-end via RelayDetector ───────────────────────────────────────────

#[test]
fn detector_emits_xff_malformed_on_bad_ip() {
    let det = make_detector_with_xff();
    let peer: IpAddr = Ipv4Addr::new(9, 9, 9, 9).into();
    let h = hdr_single(xff_name(), "totally-invalid");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(id.signals.contains(&Signal::XffMalformed));
}

#[test]
fn detector_emits_xff_too_long_on_oversized_header() {
    let det = make_detector_with_xff();
    let peer: IpAddr = Ipv4Addr::new(9, 9, 9, 9).into();
    let big = "1".repeat(MAX_HEADER_BYTES + 1);
    let h = hdr_single(xff_name(), &big);
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(id.signals.contains(&Signal::XffTooLong));
}

#[test]
fn detector_clean_chain_no_signals() {
    let det = make_detector_with_xff();
    let peer: IpAddr = Ipv4Addr::new(9, 9, 9, 9).into();
    let h = hdr_single(xff_name(), "1.2.3.4, 5.6.7.8");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(id.signals.is_empty());
    assert_eq!(id.real_ip, IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)));
}

#[test]
fn xff_validator_emits_spoof_on_private_mid_chain() {
    // Via SignalProvider directly; trusted = 10.0.0.0/8 stripped from tail.
    let v = xff_validator(&["10.0.0.0/8"]);
    let mut h = HeaderMap::new();
    h.append(xff_name(), HeaderValue::from_static("1.2.3.4, 10.0.0.1, 5.6.7.8"));
    let ctx = RelayCtx::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), &h, Instant::now());
    let signals = v.evaluate(&ctx);
    // 5.6.7.8 is the rightmost non-trusted; 10.0.0.1 is in trusted tail and
    // mid-chain before 5.6.7.8 which is public so no spoof. Actually the
    // chain [1.2.3.4, 10.0.0.1, 5.6.7.8] with trusted 10.0.0.0/8:
    // right→left: 5.6.7.8 is not trusted → real_ip=5.6.7.8, head=[1.2.3.4,10.0.0.1,5.6.7.8]
    // 10.0.0.1 in head is private → spoof_private_mid_chain=true
    assert!(signals.contains(&Signal::XffSpoofPrivate), "signals: {signals:?}");
}

#[test]
fn empty_xff_plus_x_real_ip_uses_x_real_ip() {
    // XffValidator configured with both header names; X-Real-IP fallback.
    let names = vec!["X-Forwarded-For".to_string(), "X-Real-IP".to_string()];
    let v = XffValidator::new(&names, vec![]).unwrap();
    let mut h = HeaderMap::new();
    h.append(xri_name(), HeaderValue::from_static("203.0.113.7"));
    let peer: IpAddr = Ipv4Addr::new(9, 9, 9, 9).into();
    let ctx = RelayCtx::new(peer, &h, Instant::now());
    let signals = v.evaluate(&ctx);
    // No error signals — a valid IP was in X-Real-IP.
    assert!(!signals.contains(&Signal::XffMalformed), "{signals:?}");
    assert!(!signals.contains(&Signal::XffTooLong), "{signals:?}");
}

#[test]
fn unicode_bytes_in_header_yield_malformed() {
    // Build a header with non-ASCII bytes.
    let mut h = HeaderMap::new();
    // HeaderValue::from_bytes allows arbitrary bytes (not validated as UTF-8).
    h.append(xff_name(), HeaderValue::from_bytes(&[0xf0, 0x9f, 0x92, 0xa9]).unwrap());
    let p = parse_xff_chain(&h, &[xff_name()]);
    // The value.to_str() call in parse_xff_chain returns Err for non-UTF-8 → malformed.
    assert!(p.malformed, "expected malformed for non-UTF-8 header");
}

// Verify ParsedChain::has_error aggregation.
#[test]
fn parsed_chain_has_error_aggregation() {
    let ok = ParsedChain::default();
    assert!(!ok.has_error());

    let tl = ParsedChain {
        too_long_bytes: true,
        ..Default::default()
    };
    assert!(tl.has_error());

    let tc = ParsedChain {
        too_long_count: true,
        ..Default::default()
    };
    assert!(tc.has_error());

    let mal = ParsedChain {
        malformed: true,
        ..Default::default()
    };
    assert!(mal.has_error());
}
