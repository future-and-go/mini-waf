//! FR-007 phase-07 — Full RelayDetector::evaluate end-to-end tests.
//!
//! All four providers enabled: XffValidator, ProxyChainAnalyzer,
//! AsnClassifier (StaticDb), TorExitMatcher (small TorSet).
//! Verifies combined signals and ClientIdentity.real_ip.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::redundant_pattern_matching
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use http::{HeaderMap, HeaderName, HeaderValue};
use waf_engine::relay::intel::{AsnDb, AsnRecord, DatacenterSet};
use waf_engine::relay::providers::asn_classifier::AsnClassifier;
use waf_engine::relay::providers::tor_exit::{TorExitMatcher, TorSet};
use waf_engine::relay::providers::{ProxyChainAnalyzer, XffValidator};
use waf_engine::relay::signal::Signal;
use waf_engine::relay::{ProviderRegistry, RelayConfig, RelayDetector};

// ─── test doubles ────────────────────────────────────────────────────────────

struct StaticDb(Option<AsnRecord>);
impl AsnDb for StaticDb {
    fn lookup(&self, _ip: IpAddr) -> Option<AsnRecord> {
        self.0.clone()
    }
    fn name(&self) -> &'static str {
        "e2e_static"
    }
}

// ─── builder helpers ─────────────────────────────────────────────────────────

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn xff() -> HeaderName {
    HeaderName::from_static("x-forwarded-for")
}

fn hdr(value: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.append(xff(), HeaderValue::from_str(value).unwrap());
    h
}

/// Build a full detector with all four providers.
/// `tor_ips` is the set of IPs to treat as Tor exits.
/// `asn_record` is returned by StaticDb for every lookup.
/// `dc` is the datacenter set.
/// `trusted` is the list of trusted proxy CIDRs.
fn make_full_detector(
    trusted: &[&str],
    max_depth: u8,
    asn_record: Option<AsnRecord>,
    dc: DatacenterSet,
    tor_ips: Vec<IpAddr>,
) -> RelayDetector {
    let trusted_nets: Vec<ipnet::IpNet> = trusted.iter().map(|s| s.parse().unwrap()).collect();

    let mut registry = ProviderRegistry::new();

    registry.register(Box::new(
        XffValidator::new(&["X-Forwarded-For".to_string()], trusted_nets.clone()).unwrap(),
    ));
    registry.register(Box::new(
        ProxyChainAnalyzer::new(&["X-Forwarded-For".to_string()], trusted_nets, max_depth).unwrap(),
    ));
    registry.register(Box::new(AsnClassifier::new(
        Box::new(StaticDb(asn_record)),
        Arc::new(dc),
    )));

    let mut tor_set_ips = HashSet::new();
    for ip in tor_ips {
        tor_set_ips.insert(ip);
    }
    registry.register(Box::new(TorExitMatcher::from_set(TorSet::new(tor_set_ips))));

    RelayDetector::new(Arc::new(RelayConfig::default()), registry)
}

// ─── tests ────────────────────────────────────────────────────────────────────

#[test]
fn clean_residential_chain_no_signals() {
    let det = make_full_detector(
        &[],
        10,
        Some(AsnRecord {
            asn: 7922,
            org: "COMCAST".into(),
        }),
        DatacenterSet::default(),
        vec![],
    );
    let id = det.evaluate(ip4(9, 9, 9, 9), &hdr("203.0.113.5"));
    assert_eq!(id.real_ip, ip4(203, 0, 113, 5));
    // Residential → AsnResidential, no other signals.
    assert!(id.signals.contains(&Signal::AsnResidential), "{:?}", id.signals);
    assert!(!id.signals.contains(&Signal::XffMalformed));
    assert!(!id.signals.contains(&Signal::XffSpoofPrivate));
    assert!(!id.signals.contains(&Signal::TorExit));
}

#[test]
fn datacenter_ip_yields_asn_datacenter_signal() {
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(15169);
    let det = make_full_detector(
        &[],
        10,
        Some(AsnRecord {
            asn: 15169,
            org: "GOOGLE".into(),
        }),
        dc,
        vec![],
    );
    let id = det.evaluate(ip4(8, 8, 8, 8), &HeaderMap::new());
    assert!(
        matches!(
            id.signals.iter().find(|s| matches!(s, Signal::AsnDatacenter { .. })),
            Some(_)
        ),
        "{:?}",
        id.signals
    );
}

#[test]
fn tor_exit_ip_yields_tor_exit_signal() {
    let tor_ip = ip4(198, 51, 100, 7);
    let det = make_full_detector(&[], 10, None, DatacenterSet::default(), vec![tor_ip]);
    let id = det.evaluate(tor_ip, &HeaderMap::new());
    assert!(id.signals.contains(&Signal::TorExit), "{:?}", id.signals);
    assert_eq!(id.real_ip, tor_ip);
}

/// IP that is both datacenter AND tor exit: both signals must be present.
#[test]
fn ip_both_datacenter_and_tor_emits_both_signals() {
    let dual_ip = ip4(198, 51, 100, 42);
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(64500);
    let det = make_full_detector(
        &[],
        10,
        Some(AsnRecord {
            asn: 64500,
            org: "CLOUD".into(),
        }),
        dc,
        vec![dual_ip],
    );
    let id = det.evaluate(dual_ip, &HeaderMap::new());
    assert!(id.signals.contains(&Signal::TorExit), "{:?}", id.signals);
    assert!(
        matches!(
            id.signals.iter().find(|s| matches!(s, Signal::AsnDatacenter { .. })),
            Some(_)
        ),
        "{:?}",
        id.signals
    );
}

#[test]
fn xff_spoof_and_asn_unknown_combined() {
    // Private mid-chain → XffSpoofPrivate. EmptyAsnDb → AsnUnknown.
    let det = make_full_detector(&[], 10, None, DatacenterSet::default(), vec![]);
    let peer = ip4(9, 9, 9, 9);
    let id = det.evaluate(peer, &hdr("1.2.3.4, 10.0.0.5, 5.6.7.8"));
    assert!(id.signals.contains(&Signal::XffSpoofPrivate), "{:?}", id.signals);
    assert!(id.signals.contains(&Signal::AsnUnknown), "{:?}", id.signals);
}

#[test]
fn excessive_hop_depth_and_datacenter_combined() {
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(15169);
    let det = make_full_detector(
        &[],
        2,
        Some(AsnRecord {
            asn: 15169,
            org: "GOOGLE".into(),
        }),
        dc,
        vec![],
    );
    let peer = ip4(9, 9, 9, 9);
    let id = det.evaluate(peer, &hdr("1.1.1.1, 2.2.2.2, 3.3.3.3"));
    assert!(
        matches!(
            id.signals.iter().find(|s| matches!(s, Signal::ExcessiveHopDepth(_))),
            Some(_)
        ),
        "{:?}",
        id.signals
    );
    assert!(
        matches!(
            id.signals.iter().find(|s| matches!(s, Signal::AsnDatacenter { .. })),
            Some(_)
        ),
        "{:?}",
        id.signals
    );
}

#[test]
fn trusted_tail_stripped_real_ip_correct() {
    let det = make_full_detector(&["10.0.0.0/8"], 10, None, DatacenterSet::default(), vec![]);
    let peer = ip4(10, 0, 0, 1);
    let id = det.evaluate(peer, &hdr("203.0.113.5, 10.0.0.1"));
    assert_eq!(id.real_ip, ip4(203, 0, 113, 5));
}

#[test]
fn empty_registry_falls_back_to_peer_ip() {
    let det = RelayDetector::empty();
    let peer = ip4(1, 2, 3, 4);
    let id = det.evaluate(peer, &HeaderMap::new());
    assert_eq!(id.real_ip, peer);
    assert!(id.signals.is_empty());
}

#[test]
fn xff_malformed_real_ip_falls_back_to_peer() {
    let det = make_full_detector(&[], 10, None, DatacenterSet::default(), vec![]);
    let peer = ip4(9, 9, 9, 9);
    let id = det.evaluate(peer, &hdr("not-an-ip"));
    // Malformed → chain empty → real_ip = peer.
    assert_eq!(id.real_ip, peer);
    assert!(id.signals.contains(&Signal::XffMalformed), "{:?}", id.signals);
}

#[test]
fn ipv6_real_ip_resolved_correctly() {
    let det = make_full_detector(&[], 10, None, DatacenterSet::default(), vec![]);
    let peer = ip4(9, 9, 9, 9);
    let v6: IpAddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into();
    let id = det.evaluate(peer, &hdr("2001:db8::1"));
    assert_eq!(id.real_ip, v6);
}
