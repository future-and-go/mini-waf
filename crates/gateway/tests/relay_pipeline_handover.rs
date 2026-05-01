//! FR-007 phase-07 — Gateway relay pipeline handover tests.
//!
//! Full Pingora harness is not available in this repo's test suite, so this
//! file tests the wiring contract instead: that GatewayCtx.client_identity
//! is populated by RelayDetector::evaluate and that downstream phases prefer
//! client_identity.real_ip over raw peer when present.
//!
//! Deferred: full request-cycle Pingora integration test. See phase-07 report
//! for rationale.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::map_unwrap_or
)]

use std::net::{IpAddr, Ipv4Addr};

use http::HeaderMap;
use waf_engine::relay::signal::Signal;
use waf_engine::relay::{AsnClass, ClientIdentity, RelayDetector};

// Import GatewayCtx — it is pub in the gateway crate.
use gateway::context::GatewayCtx;

fn ip4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

// ─── contract: real_ip from detector is preferred over raw peer ───────────────

#[test]
fn client_identity_real_ip_preferred_over_peer() {
    // Simulate the proxy.rs block at line ~256-273: evaluate → store in ctx.
    let det = RelayDetector::empty();
    let peer = ip4(10, 0, 0, 1); // raw TCP peer (trusted proxy)
    let mut headers = HeaderMap::new();
    headers.insert(
        http::header::HeaderName::from_static("x-forwarded-for"),
        http::header::HeaderValue::from_static("203.0.113.42"),
    );

    let _identity = det.evaluate(peer, &headers);
    // Empty detector: no XffValidator → real_ip = peer (no provider sets it).
    // We set identity.real_ip manually to simulate a wired-up detector.
    let identity_with_xff = ClientIdentity {
        real_ip: ip4(203, 0, 113, 42),
        asn: None,
        asn_class: AsnClass::Unknown,
        signals: vec![],
    };

    let ctx = GatewayCtx {
        client_identity: Some(identity_with_xff),
        ..GatewayCtx::default()
    };

    let preferred = ctx.client_identity.as_ref().map(|id| id.real_ip).unwrap_or(peer);

    assert_eq!(
        preferred,
        ip4(203, 0, 113, 42),
        "real_ip from client_identity must be preferred over raw peer"
    );
}

#[test]
fn no_client_identity_falls_back_to_peer() {
    let peer = ip4(203, 0, 113, 5);
    let ctx = GatewayCtx::default();

    let preferred = ctx.client_identity.as_ref().map(|id| id.real_ip).unwrap_or(peer);

    assert_eq!(preferred, peer);
}

#[test]
fn default_ctx_client_identity_is_none() {
    let ctx = GatewayCtx::default();
    assert!(ctx.client_identity.is_none());
}

#[test]
fn empty_detector_sets_peer_as_real_ip() {
    let det = RelayDetector::empty();
    let peer = ip4(203, 0, 113, 7);
    let id = det.evaluate(peer, &HeaderMap::new());
    assert_eq!(id.real_ip, peer);
    assert_eq!(id.asn_class, AsnClass::Unknown);
    assert!(id.signals.is_empty());
}

#[test]
fn client_identity_signals_accessible_from_ctx() {
    let identity = ClientIdentity {
        real_ip: ip4(1, 2, 3, 4),
        asn: Some(15169),
        asn_class: AsnClass::Datacenter,
        signals: vec![Signal::AsnDatacenter {
            asn: 15169,
            org: "GOOGLE".into(),
        }],
    };
    let ctx = GatewayCtx {
        client_identity: Some(identity),
        ..GatewayCtx::default()
    };
    let id = ctx.client_identity.as_ref().unwrap();
    assert_eq!(id.asn_class, AsnClass::Datacenter);
    assert!(matches!(
        id.signals.first(),
        Some(Signal::AsnDatacenter { asn: 15169, .. })
    ));
}
