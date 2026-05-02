//! FR-010 phase-09 bench — full `DeviceFpDetector::process` pipeline.
//!
//! Pipeline path measured: capture snapshot → fingerprint assemble → store
//! observe → provider dispatch → noop aggregator submit. Target from plan
//! phase-09: p99 added latency < 300µs at 5k req/s. Criterion reports
//! p50/p95/p99 in HTML output; CI nightly job snapshots numbers.
//!
//! Two scenarios: `cold` (fresh ConnCtx every iter, store sees new key)
//! and `warm` (one ConnCtx + one store, repeated observations). Warm is
//! the steady-state production case; cold stresses the assemble path.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use tokio::runtime::Runtime;

use waf_engine::device_fp::capture::ConnCtx;
use waf_engine::device_fp::config::DeviceFpConfig;
use waf_engine::device_fp::providers::{H2AnomalyProvider, UaBlocklistProvider};
use waf_engine::device_fp::{DeviceFpDetector, IdentityStore, MemoryIdentityStore, NoopAggregator, ProviderRegistry};

fn build_detector() -> DeviceFpDetector {
    let mut registry = ProviderRegistry::new();
    registry.register(Box::new(
        UaBlocklistProvider::new(vec!["(?i)curl-impersonate".to_string()]).expect("compile blocklist"),
    ));
    registry.register(Box::new(H2AnomalyProvider::new(false)));
    let store: Arc<dyn IdentityStore> = Arc::new(MemoryIdentityStore::default());
    DeviceFpDetector::new(Arc::new(DeviceFpConfig::default()), registry)
        .with_store(store)
        .with_aggregator(Arc::new(NoopAggregator))
}

fn populate_conn(conn: &ConnCtx) {
    conn.push_h2_settings(vec![(0x1, 65_536), (0x4, 6_291_456), (0x6, 262_144)]);
    conn.push_h2_window_update(0, 65_535);
}

fn bench_pipeline_warm(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let detector = build_detector();
    let conn = ConnCtx::new();
    populate_conn(&conn);
    let peer = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36";

    c.bench_function("device_fp_full_pipeline_warm", |b| {
        b.to_async(&rt).iter(|| async {
            let id = detector.process(black_box(peer), black_box(ua), black_box(&conn)).await;
            black_box(id);
        });
    });
}

fn bench_pipeline_cold(c: &mut Criterion) {
    let rt = Runtime::new().expect("tokio runtime");
    let detector = Arc::new(build_detector());
    let ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36";
    let peer = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    c.bench_function("device_fp_full_pipeline_cold", |b| {
        b.to_async(&rt).iter_batched(
            || {
                let conn = ConnCtx::new();
                populate_conn(&conn);
                conn
            },
            |conn| {
                let detector = Arc::clone(&detector);
                async move {
                    let id = detector.process(peer, ua, &conn).await;
                    black_box(id);
                }
            },
            criterion::BatchSize::SmallInput,
        );
    });
}

criterion_group!(benches, bench_pipeline_warm, bench_pipeline_cold);
criterion_main!(benches);
