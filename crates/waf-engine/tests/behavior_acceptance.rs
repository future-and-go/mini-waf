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
use waf_engine::device_fp::behavior::{
    BurstIntervalProvider, MissingRefererProvider, Recorder, RegularityProvider, ZeroDepthProvider,
};
use waf_engine::device_fp::capture::ConnCtx;
use waf_engine::device_fp::config::DeviceFpConfig;
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
    let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let provider = BurstIntervalProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("acceptance");

    // Drive 6 samples spaced 30 ms apart. We call `Recorder::record`
    // directly here rather than `gateway::behavior_record::record_sample`
    // because the gateway crate is downstream of waf-engine; this test
    // crate cannot import it. The behaviour is identical for non-empty
    // FpKey + present recorder (the only branch this test cares about).
    for i in 0..6 {
        rec.record(&k, "/p", false, false, Tier::CatchAll);
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
    let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let provider = BurstIntervalProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("negative");

    for i in 0..3 {
        rec.record(&k, "/p", false, false, Tier::CatchAll);
        if i + 1 < 3 {
            std::thread::sleep(Duration::from_millis(30));
        }
    }

    let conn = ConnCtx::new();
    let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &k);
    assert!(provider.evaluate(&ctx).is_empty());
}

/// AC2: 8 reqs same path on `/admin/critical`, no Referer → `ZeroDepth` fires.
#[test]
fn ac2_eight_critical_no_referer_emits_zero_depth() {
    let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let provider = ZeroDepthProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("ac2");

    for _ in 0..8 {
        rec.record(&k, "/admin/critical", false, false, Tier::Critical);
    }

    let conn = ConnCtx::new();
    let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &k);
    let signals = provider.evaluate(&ctx);

    assert_eq!(signals.len(), 1, "expected one ZeroDepth signal, got {signals:?}");
    assert!(matches!(signals.first(), Some(Signal::ZeroDepth { samples }) if *samples >= 4));
}

/// AC3: first GET on `/dashboard/profile` with no Referer / no prefetch hint
/// → `MissingReferer` fires.
#[test]
fn ac3_first_unreferenced_nav_emits_missing_referer() {
    let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let provider = MissingRefererProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("ac3");

    rec.record(&k, "/dashboard/profile", false, false, Tier::High);

    let conn = ConnCtx::new();
    let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &k);
    let signals = provider.evaluate(&ctx);

    assert_eq!(signals.len(), 1);
    assert!(matches!(signals.first(), Some(Signal::MissingReferer)));
}

/// AC4: human-like trace — varied paths, varied intervals, Referer chain →
/// every Phase-3/4 classifier stays silent.
#[test]
fn ac4_human_trace_emits_no_signals() {
    let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let burst = BurstIntervalProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let regularity = RegularityProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let zero_depth = ZeroDepthProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let missing_referer = MissingRefererProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let k = key("ac4");

    // Realistic trace: varied paths, varied intervals (jitter), Referer set
    // on every nav after the entry. Entry is `/login` (exempt) so the
    // first-request missing_referer guard wouldn't fire even bare.
    let trace = [
        ("/login", false, 0u64),
        ("/dashboard", true, 2300),
        ("/dashboard/profile", true, 1800),
        ("/dashboard/orders", true, 4100),
        ("/dashboard/orders/42", true, 950),
        ("/dashboard/profile", true, 2700),
    ];
    for (i, (path, had_referer, delay)) in trace.iter().enumerate() {
        if i > 0 {
            std::thread::sleep(Duration::from_millis(*delay));
        }
        rec.record(&k, path, *had_referer, false, Tier::High);
    }

    let conn = ConnCtx::new();
    let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &k);
    assert!(burst.evaluate(&ctx).is_empty(), "burst_interval fired on human trace");
    assert!(regularity.evaluate(&ctx).is_empty(), "regularity fired on human trace");
    assert!(zero_depth.evaluate(&ctx).is_empty(), "zero_depth fired on human trace");
    assert!(
        missing_referer.evaluate(&ctx).is_empty(),
        "missing_referer fired on human trace"
    );
}
