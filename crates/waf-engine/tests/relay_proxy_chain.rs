//! FR-007 phase-07 — ProxyChainAnalyzer integration tests.
//!
//! Builds a registry with only `ProxyChainAnalyzer` and verifies:
//! - effective_depth ≤ max → no signal
//! - effective_depth > max → ExcessiveHopDepth(n) with correct n
//! - trusted-tail strip math (reduces effective depth)

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::net::{IpAddr, Ipv4Addr};

use http::{HeaderMap, HeaderName, HeaderValue};
use waf_engine::relay::providers::ProxyChainAnalyzer;
use waf_engine::relay::signal::{RelayCtx, Signal, SignalProvider};
use waf_engine::relay::{ProviderRegistry, RelayConfig, RelayDetector};

fn xff() -> HeaderName {
    HeaderName::from_static("x-forwarded-for")
}

fn hdr(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.append(xff(), HeaderValue::from_str(value).unwrap());
    h
}

fn peer() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))
}

// ─── direct ProxyChainAnalyzer tests ────────────────────────────────────────

#[test]
fn under_cap_is_silent() {
    let p = ProxyChainAnalyzer::new(&["X-Forwarded-For".into()], vec![], 3).unwrap();
    let h = hdr("1.1.1.1, 2.2.2.2");
    let ctx = RelayCtx::new(peer(), &h, std::time::Instant::now());
    assert!(p.evaluate(&ctx).is_empty());
}

#[test]
fn at_cap_is_silent() {
    let p = ProxyChainAnalyzer::new(&["X-Forwarded-For".into()], vec![], 3).unwrap();
    let h = hdr("1.1.1.1, 2.2.2.2, 3.3.3.3");
    let ctx = RelayCtx::new(peer(), &h, std::time::Instant::now());
    assert!(p.evaluate(&ctx).is_empty());
}

#[test]
fn over_cap_emits_excessive_hop_depth_with_correct_n() {
    let p = ProxyChainAnalyzer::new(&["X-Forwarded-For".into()], vec![], 3).unwrap();
    let h = hdr("1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4");
    let ctx = RelayCtx::new(peer(), &h, std::time::Instant::now());
    let signals = p.evaluate(&ctx);
    assert_eq!(signals, vec![Signal::ExcessiveHopDepth(4)]);
}

#[test]
fn trusted_tail_strip_reduces_effective_depth() {
    // Chain: [1.1.1.1, 2.2.2.2, 10.0.0.1, 10.0.0.2]
    // trusted 10.0.0.0/8 → strips last 2 → effective_depth=2, max=3 → silent.
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let p = ProxyChainAnalyzer::new(&["X-Forwarded-For".into()], trusted, 3).unwrap();
    let h = hdr("1.1.1.1, 2.2.2.2, 10.0.0.1, 10.0.0.2");
    let ctx = RelayCtx::new(peer(), &h, std::time::Instant::now());
    assert!(p.evaluate(&ctx).is_empty());
}

#[test]
fn trusted_tail_strip_still_exceeds_cap() {
    // Chain: [1.1.1.1, 2.2.2.2, 3.3.3.3, 10.0.0.1]
    // trusted 10.0.0.0/8 → strips 1 → effective_depth=3, max=2 → signal.
    let trusted: Vec<ipnet::IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
    let p = ProxyChainAnalyzer::new(&["X-Forwarded-For".into()], trusted, 2).unwrap();
    let h = hdr("1.1.1.1, 2.2.2.2, 3.3.3.3, 10.0.0.1");
    let ctx = RelayCtx::new(peer(), &h, std::time::Instant::now());
    let signals = p.evaluate(&ctx);
    assert_eq!(signals, vec![Signal::ExcessiveHopDepth(3)]);
}

// ─── via ProviderRegistry / RelayDetector ───────────────────────────────────

fn make_detector_proxy_only(max_depth: u8) -> RelayDetector {
    let yaml = format!(
        r#"
relay_detection:
  trusted_proxies: []
  max_chain_depth: {max_depth}
  signals:
    enabled: ["proxy_chain"]
"#
    );
    let cfg = RelayConfig::from_yaml_str(&yaml).unwrap();
    let registry = ProviderRegistry::from_config(&cfg).unwrap();
    RelayDetector::new(cfg, registry)
}

#[test]
fn registry_proxy_chain_silent_under_cap() {
    let det = make_detector_proxy_only(5);
    let h = hdr("1.1.1.1, 2.2.2.2");
    let id = det.evaluate(peer(), &h);
    assert!(id.signals.is_empty());
}

#[test]
fn registry_proxy_chain_emits_over_cap() {
    let det = make_detector_proxy_only(2);
    let h = hdr("1.1.1.1, 2.2.2.2, 3.3.3.3");
    let id = det.evaluate(peer(), &h);
    assert!(
        matches!(id.signals.first(), Some(Signal::ExcessiveHopDepth(3))),
        "signals: {:?}",
        id.signals
    );
}

#[test]
fn empty_chain_peer_is_real_ip() {
    let det = make_detector_proxy_only(3);
    let id = det.evaluate(peer(), &HeaderMap::new());
    assert_eq!(id.real_ip, peer());
    assert!(id.signals.is_empty());
}
