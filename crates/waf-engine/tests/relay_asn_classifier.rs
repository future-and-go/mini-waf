//! FR-007 phase-07 — AsnClassifier integration tests.
//!
//! Uses a `StaticDb` helper (mirrors the one in `asn_classifier.rs` unit tests
//! but defined here for integration-test access). Verifies override precedence,
//! CIDR-match, DB-miss, and the "compromised feed" adversarial case.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use http::HeaderMap;
use waf_engine::relay::intel::{AsnDb, AsnRecord, DatacenterSet, EmptyAsnDb};
use waf_engine::relay::providers::AsnClassifier;
use waf_engine::relay::signal::{RelayCtx, Signal, SignalProvider};

// ─── test fixture ───────────────────────────────────────────────────────────

struct StaticDb(Option<AsnRecord>);

impl AsnDb for StaticDb {
    fn lookup(&self, _ip: IpAddr) -> Option<AsnRecord> {
        self.0.clone()
    }
    fn name(&self) -> &'static str {
        "static_test"
    }
}

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn eval(db: Box<dyn AsnDb>, dc: DatacenterSet, target: IpAddr) -> Vec<Signal> {
    let classifier = AsnClassifier::new(db, Arc::new(dc));
    let headers = Box::leak(Box::new(HeaderMap::new()));
    let ctx = RelayCtx::new(target, headers, std::time::Instant::now());
    classifier.evaluate(&ctx)
}

// ─── tests ───────────────────────────────────────────────────────────────────

#[test]
fn db_miss_yields_asn_unknown() {
    let signals = eval(Box::new(EmptyAsnDb), DatacenterSet::default(), ip(8, 8, 8, 8));
    assert_eq!(signals, vec![Signal::AsnUnknown]);
}

#[test]
fn asn_in_dc_asn_ids_yields_datacenter() {
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(15169);
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 15169,
        org: "GOOGLE".into(),
    })));
    let signals = eval(db, dc, ip(8, 8, 8, 8));
    assert_eq!(
        signals,
        vec![Signal::AsnDatacenter {
            asn: 15169,
            org: "GOOGLE".into(),
        }]
    );
}

#[test]
fn cidr_match_yields_datacenter_when_asn_unknown_in_dc_set() {
    // ASN 64500 is NOT in dc.asn_ids, but the CIDR 203.0.113.0/24 is in dc.cidrs.
    let mut dc = DatacenterSet::default();
    dc.cidrs
        .insert("203.0.113.0/24".parse::<ip_network::IpNetwork>().unwrap(), ());
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 64500,
        org: "VENDOR".into(),
    })));
    let signals = eval(db, dc, ip(203, 0, 113, 5));
    assert!(
        matches!(signals.first(), Some(Signal::AsnDatacenter { asn: 64500, .. })),
        "{signals:?}"
    );
}

#[test]
fn operator_allow_wins_over_dc_asn_ids() {
    let mut dc = DatacenterSet::default();
    dc.asn_ids.insert(15169);
    dc.operator_allow.insert(15169); // override
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 15169,
        org: "GOOGLE".into(),
    })));
    let signals = eval(db, dc, ip(8, 8, 8, 8));
    assert_eq!(signals, vec![Signal::AsnResidential]);
}

#[test]
fn operator_allow_wins_over_operator_deny() {
    // Both deny AND allow set: allow wins per brainstorm §4.5.
    let mut dc = DatacenterSet::default();
    dc.operator_deny.insert(15169);
    dc.operator_allow.insert(15169);
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 15169,
        org: "GOOGLE".into(),
    })));
    let signals = eval(db, dc, ip(8, 8, 8, 8));
    assert_eq!(signals, vec![Signal::AsnResidential]);
}

#[test]
fn operator_deny_plus_non_dc_asn_yields_datacenter() {
    let mut dc = DatacenterSet::default();
    dc.operator_deny.insert(7922); // ISP flagged by operator
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 7922,
        org: "COMCAST".into(),
    })));
    let signals = eval(db, dc, ip(73, 1, 2, 3));
    assert_eq!(
        signals,
        vec![Signal::AsnDatacenter {
            asn: 7922,
            org: "COMCAST".into(),
        }]
    );
}

#[test]
fn plain_residential_asn_not_in_any_set_yields_residential() {
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 7922,
        org: "COMCAST".into(),
    })));
    let signals = eval(db, DatacenterSet::default(), ip(73, 1, 2, 3));
    assert_eq!(signals, vec![Signal::AsnResidential]);
}

/// Adversarial: ASN feed claims ASN 99999 is a datacenter ASN (feed
/// compromise / mis-classification). Operator has added 99999 to
/// `operator_allow` → residential wins regardless.
#[test]
fn compromised_feed_overridden_by_operator_allow() {
    let mut dc = DatacenterSet::default();
    // Feed / built-in DC set says 99999 is a datacenter ASN.
    dc.asn_ids.insert(99999);
    // Operator knows this is actually a residential ISP and overrides.
    dc.operator_allow.insert(99999);
    let db = Box::new(StaticDb(Some(AsnRecord {
        asn: 99999,
        org: "RESIDENTIAL_ISP".into(),
    })));
    let signals = eval(db, dc, ip(1, 2, 3, 4));
    assert_eq!(
        signals,
        vec![Signal::AsnResidential],
        "operator_allow must win over compromised DC feed"
    );
}

/// DB miss (EmptyAsnDb) → AsnUnknown (not Residential).
#[test]
fn empty_db_yields_unknown_not_residential() {
    let signals = eval(Box::new(EmptyAsnDb), DatacenterSet::default(), ip(1, 2, 3, 4));
    assert_eq!(signals, vec![Signal::AsnUnknown]);
    assert!(!signals.contains(&Signal::AsnResidential));
}
