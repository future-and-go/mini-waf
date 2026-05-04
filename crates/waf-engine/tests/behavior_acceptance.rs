//! FR-011 acceptance — exercises the full pipeline built in Phases 1-3:
//! Recorder write → snapshot clone → provider eval → Signal emission.
//!
//! Stops short of spinning a real Pingora `Session`. The Phase-2 integration
//! point (`gateway::behavior_record::record_sample`) is the same code path
//! the proxy exercises in production; testing it directly avoids the heavy
//! Pingora fixture cost (`gateway` crate notes that Pingora-driven E2E tests
//! are deferred). This file's mandate is to validate Phases 1-3 cohere; that
//! is satisfied without a real socket.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use waf_common::tier::Tier;
use waf_engine::device_fp::SignalProvider;
use waf_engine::device_fp::behavior::{BehaviorConfig, BurstIntervalProvider, Recorder};
use waf_engine::device_fp::capture::ConnCtx;
use waf_engine::device_fp::signal::Signal;
use waf_engine::device_fp::types::{DeviceCtx, FingerprintValue, FpKey};

fn key(tag: &str) -> FpKey {
    FpKey {
        ja3: Some(FingerprintValue::new(tag)),
        ja4: None,
        h2_akamai: None,
    }
}

#[test]
fn six_records_at_thirty_ms_emit_burst_interval() {
    // Plan §Success Criteria: 6 reqs @ 30 ms apart → +15 risk delta observed.
    // We assert the *signal* (the provider's contract); the +15 risk delta is
    // the operator-configured weight that the FR-025 aggregator applies.
    let cfg = Arc::new(ArcSwap::from_pointee(BehaviorConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let provider = BurstIntervalProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("acceptance");

    // Drive 6 samples spaced 30 ms apart. We call `Recorder::record`
    // directly here rather than `gateway::behavior_record::record_sample`
    // because the gateway crate is downstream of waf-engine; this test
    // crate cannot import it. The behaviour is identical for non-empty
    // FpKey + present recorder (the only branch this test cares about).
    for i in 0..6 {
        rec.record(&k, "/p", false, Tier::CatchAll);
        if i + 1 < 6 {
            std::thread::sleep(Duration::from_millis(30));
        }
    }

    // Snapshot must be present and saturated to 6 samples.
    let snap = rec.snapshot(&k).expect("recorder must hold snapshot");
    assert_eq!(snap.samples.len(), 6, "expected 6 samples, got {}", snap.samples.len());

    // Eval the provider exactly as the per-request fan-out would.
    let conn = ConnCtx::new();
    let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &k);
    let signals = provider.evaluate(&ctx);

    assert_eq!(signals.len(), 1, "expected exactly one BurstInterval signal");
    match signals.first() {
        Some(Signal::BurstInterval { count }) => {
            assert!(*count >= 5, "burst count {count} must be ≥ min_consecutive (5)");
        }
        other => panic!("wrong signal variant: {other:?}"),
    }
}

#[test]
fn three_records_silent_below_threshold_count() {
    // Negative control: 3 samples → 2 intervals < min_consecutive=5 → silent.
    let cfg = Arc::new(ArcSwap::from_pointee(BehaviorConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let provider = BurstIntervalProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("negative");

    for i in 0..3 {
        rec.record(&k, "/p", false, Tier::CatchAll);
        if i + 1 < 3 {
            std::thread::sleep(Duration::from_millis(30));
        }
    }

    let conn = ConnCtx::new();
    let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &k);
    assert!(provider.evaluate(&ctx).is_empty());
}
