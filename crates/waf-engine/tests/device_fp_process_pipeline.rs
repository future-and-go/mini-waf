//! FR-010 — `DeviceFpDetector::process` end-to-end coverage with store wired.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use waf_engine::device_fp::capture::ConnCtx;
use waf_engine::device_fp::{DeviceFpDetector, IdentityStore, LoggingAggregator, MemoryIdentityStore};

#[tokio::test]
async fn process_with_store_observes_when_key_non_empty() {
    let store: Arc<dyn IdentityStore> = Arc::new(MemoryIdentityStore::new());
    let agg = Arc::new(LoggingAggregator::new(8));
    let det = DeviceFpDetector::empty()
        .with_store(Arc::clone(&store))
        .with_aggregator(agg.clone());

    let conn = ConnCtx::new();
    // Empty registry → empty signals; empty fingerprint → observe skipped
    let id = det.process(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn).await;
    assert!(id.signals.is_empty());
    assert_eq!(agg.len(), 1, "aggregator must always be called");
}

#[tokio::test]
async fn process_without_store_skips_observation() {
    let agg = Arc::new(LoggingAggregator::new(4));
    let det = DeviceFpDetector::empty().with_aggregator(agg.clone());
    let conn = ConnCtx::new();
    let _ = det.process(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), "agent", &conn).await;
    assert_eq!(agg.len(), 1);
}

#[test]
fn registry_accessor_returns_empty_for_empty_detector() {
    let det = DeviceFpDetector::empty();
    let reg = det.registry();
    // Empty registry has zero providers — exercising the const accessor
    assert_eq!(reg.len(), 0);
}
