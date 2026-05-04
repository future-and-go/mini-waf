//! FR-011 phase-06 bench — recorder write + 4-classifier eval hot path.
//!
//! Measures two hot paths:
//!   * `behavior_record_only` — `Recorder::record` solo (sub-1µs target).
//!   * `behavior_full_eval` — `record` + 4 provider evaluations (the
//!     per-request work the gateway does); plan budget < 5 µs at p99 on a
//!     quiet machine.
//!
//! `FpKey` is pinned and pre-warmed (16 prior records) so the warm-window
//! steady state — what production sees once an actor is established — is
//! what we measure.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use waf_common::tier::Tier;
use waf_engine::device_fp::SignalProvider;
use waf_engine::device_fp::behavior::{
    BurstIntervalProvider, MissingRefererProvider, Recorder, RegularityProvider, ZeroDepthProvider,
};
use waf_engine::device_fp::capture::ConnCtx;
use waf_engine::device_fp::config::DeviceFpConfig;
use waf_engine::device_fp::types::{DeviceCtx, FingerprintValue, FpKey};

fn pinned_key() -> FpKey {
    FpKey {
        ja3: Some(FingerprintValue::new("bench-ja3")),
        ja4: None,
        h2_akamai: None,
    }
}

fn warm_recorder() -> (Arc<Recorder>, Arc<ArcSwap<DeviceFpConfig>>, FpKey) {
    let cfg = Arc::new(ArcSwap::from_pointee(DeviceFpConfig::default()));
    let rec = Arc::new(Recorder::new(Arc::clone(&cfg)));
    let key = pinned_key();
    // Pre-fill the ring so we measure steady state, not first-record cost.
    for i in 0..16u32 {
        rec.record(&key, "/dashboard", true, false, Tier::High);
        black_box(i);
    }
    (rec, cfg, key)
}

fn bench_record_only(c: &mut Criterion) {
    let (rec, _cfg, key) = warm_recorder();
    c.bench_function("behavior_record_only", |b| {
        b.iter(|| {
            rec.record(black_box(&key), black_box("/dashboard"), true, false, Tier::High);
        });
    });
}

fn bench_full_eval(c: &mut Criterion) {
    let (rec, cfg, key) = warm_recorder();
    let burst = BurstIntervalProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let regularity = RegularityProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let zero_depth = ZeroDepthProvider::new(Arc::clone(&rec), Arc::clone(&cfg));
    let missing_referer = MissingRefererProvider::new(Arc::clone(&rec), Arc::clone(&cfg));

    let conn = ConnCtx::new();
    let peer = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let ctx = DeviceCtx::new(peer, "ua", &conn, &key);

    c.bench_function("behavior_full_eval", |b| {
        b.iter(|| {
            rec.record(black_box(&key), black_box("/dashboard"), true, false, Tier::High);
            black_box(burst.evaluate(&ctx));
            black_box(regularity.evaluate(&ctx));
            black_box(zero_depth.evaluate(&ctx));
            black_box(missing_referer.evaluate(&ctx));
        });
    });
}

criterion_group!(benches, bench_record_only, bench_full_eval);
criterion_main!(benches);
