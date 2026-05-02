//! FR-010 phase-07 — end-to-end pipeline integration test.
//!
//! Wires `DeviceFpDetector::process` through the full chain
//! (capture → fingerprint → store observe → providers → aggregator)
//! and asserts the resolved signals reach a `LoggingAggregator`.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use waf_engine::device_fp::capture::ConnCtx;
use waf_engine::device_fp::config::DeviceFpConfig;
use waf_engine::device_fp::providers::{H2AnomalyProvider, UaBlocklistProvider};
use waf_engine::device_fp::signal::{H2AnomalyReason, Signal};
use waf_engine::device_fp::{
    DeviceFpDetector, IdentityStore, LoggingAggregator, MemoryIdentityStore, ProviderRegistry,
};

#[tokio::test]
async fn process_emits_h2_anomaly_and_ua_blocklist_into_aggregator() {
    // Build a registry with the two providers exercised by this test.
    let mut registry = ProviderRegistry::new();
    registry.register(Box::new(
        UaBlocklistProvider::new(vec!["(?i)curl-impersonate".to_string()]).expect("compile blocklist"),
    ));
    registry.register(Box::new(H2AnomalyProvider::new(false)));

    // ConnCtx with a deliberately-malformed h2 frame (zero increment
    // WINDOW_UPDATE → RFC 7540 §6.9 violation).
    let conn = ConnCtx::new();
    conn.push_h2_window_update(1, 0);

    // LoggingAggregator captures every submission for later assertion.
    let aggregator = Arc::new(LoggingAggregator::new(8));
    let store: Arc<dyn IdentityStore> = Arc::new(MemoryIdentityStore::default());
    let detector = DeviceFpDetector::new(Arc::new(DeviceFpConfig::default()), registry)
        .with_store(store)
        .with_aggregator(aggregator.clone());

    let id = detector
        .process(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), "curl-impersonate/1.0", &conn)
        .await;

    assert!(
        id.signals.iter().any(|s| matches!(
            s,
            Signal::H2Anomaly {
                reason: H2AnomalyReason::ZeroWindowUpdate
            }
        )),
        "expected H2Anomaly::ZeroWindowUpdate, got {:?}",
        id.signals
    );
    assert!(
        id.signals.iter().any(|s| matches!(s, Signal::UaBlocklisted { .. })),
        "expected UaBlocklisted, got {:?}",
        id.signals
    );

    let snap = aggregator.snapshot();
    assert_eq!(snap.len(), 1);
    let captured = snap.first().expect("aggregator should have one entry");
    assert_eq!(captured.signals, id.signals);
}

#[tokio::test]
async fn process_with_default_aggregator_does_not_panic() {
    // Smoke-check the no-aggregator default path used at boot.
    let detector = DeviceFpDetector::empty();
    let conn = ConnCtx::new();
    let _ = detector.process(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn).await;
}
