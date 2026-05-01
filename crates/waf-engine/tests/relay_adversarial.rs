//! FR-007 phase-07 — Adversarial Test Matrix (brainstorm §6).
//!
//! Each test encodes one row of the 12-case matrix verbatim.
//! Registry: XffValidator + ProxyChainAnalyzer + AsnClassifier(StaticDb/EmptyAsnDb).
//! MAX_CHAIN_DEPTH=10 unless a case requires otherwise.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use http::{HeaderMap, HeaderName, HeaderValue};
use waf_engine::relay::intel::{AsnDb, AsnRecord, DatacenterSet, EmptyAsnDb};
use waf_engine::relay::providers::asn_classifier::AsnClassifier;
use waf_engine::relay::providers::parse::MAX_HEADER_BYTES;
use waf_engine::relay::providers::{ProxyChainAnalyzer, XffValidator};
use waf_engine::relay::signal::Signal;
use waf_engine::relay::{ClientIdentity, ProviderRegistry, RelayConfig, RelayDetector};

// ─── helpers ─────────────────────────────────────────────────────────────────

struct StaticDb(Option<AsnRecord>);
impl AsnDb for StaticDb {
    fn lookup(&self, _ip: IpAddr) -> Option<AsnRecord> {
        self.0.clone()
    }
    fn name(&self) -> &'static str {
        "static_adversarial"
    }
}

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn xff_header() -> HeaderName {
    HeaderName::from_static("x-forwarded-for")
}

fn xri_header() -> HeaderName {
    HeaderName::from_static("x-real-ip")
}

/// Build a detector with XffValidator + ProxyChainAnalyzer + AsnClassifier(EmptyAsnDb).
/// `trusted` is a list of CIDR strings for trusted proxies.
fn make_detector(trusted: &[&str], max_depth: u8) -> RelayDetector {
    let trusted_str: Vec<String> = trusted.iter().map(|s| format!("\"{s}\"")).collect();
    let yaml = format!(
        r#"
relay_detection:
  trusted_proxies: [{}]
  max_chain_depth: {max_depth}
  signals:
    enabled: ["xff_validator", "proxy_chain"]
"#,
        trusted_str.join(", ")
    );
    let cfg = RelayConfig::from_yaml_str(&yaml).unwrap();
    let mut registry = ProviderRegistry::from_config(&cfg).unwrap();
    // Add AsnClassifier with EmptyAsnDb.
    registry.register(Box::new(AsnClassifier::new(
        Box::new(EmptyAsnDb),
        Arc::new(DatacenterSet::default()),
    )));
    RelayDetector::new(cfg, registry)
}

fn hdr_xff(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.append(xff_header(), HeaderValue::from_str(value).unwrap());
    h
}

// ─── Matrix row 1: Trusted-proxy spoof tail ──────────────────────────────────
// XFF: "attacker, trusted"  →  real_ip=attacker, no spoof signal

#[test]
fn trusted_proxy_spoof_tail_real_ip_is_attacker_no_spoof_signal() {
    // trusted=192.168.1.1/32 simulates the known proxy at the tail.
    let det = make_detector(&["192.168.1.0/24"], 10);
    let peer = ip4(192, 168, 1, 1);
    // XFF: attacker at left, trusted at right.
    let h = hdr_xff("203.0.113.5, 192.168.1.1");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert_eq!(id.real_ip, ip4(203, 0, 113, 5), "real_ip must be attacker");
    assert!(
        !id.signals.contains(&Signal::XffSpoofPrivate),
        "no spoof signal: signals={:?}",
        id.signals
    );
}

// ─── Matrix row 2: Trusted-proxy spoof tail with private mid ─────────────────
// XFF: "attacker, 10.0.0.5, trusted"  →  real_ip=attacker, XffSpoofPrivate

#[test]
fn trusted_proxy_spoof_tail_with_private_mid_emits_spoof_private() {
    // Trust only the specific LB address — 10.0.0.5 stays untrusted private,
    // so derive_real_ip flags spoof_private_mid_chain on the remaining head.
    let det = make_detector(&["10.0.0.1/32"], 10);
    let peer = ip4(10, 0, 0, 1);
    // attacker at left, RFC1918 in middle, trusted stripped at right.
    let h = hdr_xff("203.0.113.5, 10.0.0.5, 10.0.0.1");
    let id: ClientIdentity = det.evaluate(peer, &h);
    // 10.0.0.1 stripped (trusted), 10.0.0.5 is in remaining head and private.
    assert!(
        id.signals.contains(&Signal::XffSpoofPrivate),
        "XffSpoofPrivate expected; signals={:?}",
        id.signals
    );
}

// ─── Matrix row 3: Double XFF header (folded) ────────────────────────────────
// Two XFF headers → concatenated correctly, both IPs present in chain.

#[test]
fn double_xff_header_folded_concatenated_correctly() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    let mut h = HeaderMap::new();
    h.append(xff_header(), HeaderValue::from_static("1.2.3.4"));
    h.append(xff_header(), HeaderValue::from_static("5.6.7.8"));
    let id: ClientIdentity = det.evaluate(peer, &h);
    // Both IPs were in the chain; real_ip = last = 5.6.7.8 (rightmost non-trusted).
    assert_eq!(id.real_ip, ip4(5, 6, 7, 8));
    assert!(
        !id.signals.contains(&Signal::XffMalformed),
        "no malformed signal for valid folded headers"
    );
}

// ─── Matrix row 4: RFC1918 mid-chain after public ────────────────────────────
// XFF: "1.2.3.4, 10.0.0.1, 5.6.7.8"  →  XffSpoofPrivate

#[test]
fn rfc1918_mid_chain_after_public_emits_spoof_private() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    // No trusted proxies: real_ip = 5.6.7.8 (rightmost), head includes 10.0.0.1.
    let h = hdr_xff("1.2.3.4, 10.0.0.1, 5.6.7.8");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(
        id.signals.contains(&Signal::XffSpoofPrivate),
        "XffSpoofPrivate expected; signals={:?}",
        id.signals
    );
}

// ─── Matrix row 5: Chain > 32 entries ────────────────────────────────────────
// → XffTooLong, no panic, entries empty.

#[test]
fn chain_over_32_entries_yields_xff_too_long_no_panic() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    let many: Vec<String> = (0..=32).map(|i| format!("10.0.{}.{}", i / 256, i % 256)).collect();
    let h = hdr_xff(&many.join(", "));
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(
        id.signals.contains(&Signal::XffTooLong),
        "XffTooLong expected; signals={:?}",
        id.signals
    );
}

// ─── Matrix row 6: Header > 8KB ──────────────────────────────────────────────
// → rejected at byte cap, XffTooLong.

#[test]
fn header_over_8kb_rejected_at_byte_cap_xff_too_long() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    let big = "1".repeat(MAX_HEADER_BYTES + 1);
    let h = hdr_xff(&big);
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(
        id.signals.contains(&Signal::XffTooLong),
        "XffTooLong expected; signals={:?}",
        id.signals
    );
}

// ─── Matrix row 7: IPv6 zone-id ──────────────────────────────────────────────
// fe80::1%eth0 → parsed, zone stripped (no malformed).

#[test]
fn ipv6_zone_id_parsed_zone_stripped_no_error() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    let h = hdr_xff("fe80::1%eth0");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(
        !id.signals.contains(&Signal::XffMalformed),
        "no malformed for zone-id: {:?}",
        id.signals
    );
    let expected_v6: IpAddr = "fe80::1".parse::<Ipv6Addr>().unwrap().into();
    assert_eq!(id.real_ip, expected_v6);
}

// ─── Matrix row 8: Bracketed IPv6 with port ──────────────────────────────────
// [2001:db8::1]:443 → parsed correctly.

#[test]
fn bracketed_ipv6_with_port_parsed_correctly() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    let h = hdr_xff("[2001:db8::1]:443");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(
        !id.signals.contains(&Signal::XffMalformed),
        "no malformed for bracketed IPv6: {:?}",
        id.signals
    );
    let expected: IpAddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into();
    assert_eq!(id.real_ip, expected);
}

// ─── Matrix row 9: Unicode bytes in header ───────────────────────────────────
// → parser rejects, XffMalformed.

#[test]
fn unicode_bytes_in_header_yield_xff_malformed() {
    let det = make_detector(&[], 10);
    let peer = ip4(9, 9, 9, 9);
    let mut h = HeaderMap::new();
    // Non-UTF-8 bytes injected via from_bytes.
    h.append(
        xff_header(),
        HeaderValue::from_bytes(&[0xc3, 0x28]).unwrap(), // invalid UTF-8
    );
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert!(
        id.signals.contains(&Signal::XffMalformed),
        "XffMalformed expected; signals={:?}",
        id.signals
    );
}

// ─── Matrix row 10: Empty XFF + only X-Real-IP ───────────────────────────────
// → uses X-Real-IP value as real_ip.

#[test]
fn empty_xff_only_x_real_ip_uses_x_real_ip() {
    // Configure XffValidator with both header names.
    let cfg_yaml = r#"
relay_detection:
  trusted_proxies: []
  max_chain_depth: 10
  headers:
    forwarded_for: ["X-Forwarded-For", "X-Real-IP"]
  signals:
    enabled: ["xff_validator"]
"#;
    let cfg = RelayConfig::from_yaml_str(cfg_yaml).unwrap();
    let registry = ProviderRegistry::from_config(&cfg).unwrap();
    let det = RelayDetector::new(cfg, registry);

    let peer = ip4(9, 9, 9, 9);
    let mut h = HeaderMap::new();
    h.append(xri_header(), HeaderValue::from_static("203.0.113.7"));
    let id: ClientIdentity = det.evaluate(peer, &h);

    assert_eq!(id.real_ip, ip4(203, 0, 113, 7));
    assert!(
        !id.signals.contains(&Signal::XffMalformed),
        "no malformed: {:?}",
        id.signals
    );
}

// ─── Matrix row 11: All chain entries trusted ────────────────────────────────
// → real_ip = peer_ip, no signals.

#[test]
fn all_chain_entries_trusted_real_ip_is_peer_no_signals() {
    let det = make_detector(&["10.0.0.0/8"], 10);
    let peer = ip4(9, 9, 9, 9);
    let h = hdr_xff("10.0.0.1, 10.0.0.2");
    let id: ClientIdentity = det.evaluate(peer, &h);
    assert_eq!(id.real_ip, peer, "must fall back to peer when all entries trusted");
    // Only AsnUnknown (from EmptyAsnDb) expected — no XFF signals.
    let xff_signals: Vec<_> = id.signals.iter().filter(|s| !matches!(s, Signal::AsnUnknown)).collect();
    assert!(xff_signals.is_empty(), "unexpected signals: {xff_signals:?}");
}

// ─── Matrix row 12: ASN feed compromised, operator allow override ─────────────
// DC feed claims ASN 99999 is datacenter; operator allow → classified Residential.

#[test]
fn compromised_feed_operator_allow_override_classified_residential() {
    // Build registry manually with a StaticDb that returns ASN 99999
    // and a DatacenterSet that also lists 99999 as DC (the "compromise").
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(99999);
    dc.operator_allow.insert(99999); // operator override wins

    let mut registry = ProviderRegistry::new();
    registry.register(Box::new(
        XffValidator::new(&["X-Forwarded-For".to_string()], vec![]).unwrap(),
    ));
    registry.register(Box::new(
        ProxyChainAnalyzer::new(&["X-Forwarded-For".to_string()], vec![], 10).unwrap(),
    ));
    registry.register(Box::new(AsnClassifier::new(
        Box::new(StaticDb(Some(AsnRecord {
            asn: 99999,
            org: "RESIDENTIAL_ISP".into(),
        }))),
        Arc::new(dc),
    )));

    let det = RelayDetector::new(Arc::new(RelayConfig::default()), registry);
    let id = det.evaluate(ip4(1, 2, 3, 4), &HeaderMap::new());

    assert!(
        id.signals.contains(&Signal::AsnResidential),
        "operator_allow must override compromised DC feed; signals={:?}",
        id.signals
    );
    assert!(
        !id.signals.iter().any(|s| matches!(s, Signal::AsnDatacenter { .. })),
        "AsnDatacenter must not be emitted when operator_allow set; signals={:?}",
        id.signals
    );
}
