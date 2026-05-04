//! FR-012 phase-04 bench — `TxStore` record + classifier eval hot path.
//!
//! Measures per-request overhead with populated `DashMap` (10k sessions).
//! Target: p99 < 100µs for the full `check()` call.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_possible_truncation)]

use std::sync::Arc;

use arc_swap::ArcSwap;
use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use waf_engine::checks::tx_velocity::config::{ClassifierConfigs, SequenceCfg, VelocityCfg};
use waf_engine::checks::tx_velocity::role_tagger::RoleTagger;
use waf_engine::checks::tx_velocity::session_key::{SessionIdent, SessionKey};
use waf_engine::checks::tx_velocity::{EndpointRole, TxStore, TxVelocityConfig, default_classifiers};
use waf_engine::device_fp::aggregator::NoopAggregator;

fn bench_config() -> TxVelocityConfig {
    TxVelocityConfig {
        enabled: true,
        signal_cooldown_ms: 60_000, // Long cooldown to avoid signal spam
        session_ttl_secs: 3600,
        session_cookie: "SESSIONID".to_string(),
        janitor_period_secs: 60,
        role_tagger: RoleTagger::empty(),
        classifiers: ClassifierConfigs {
            sequence: Some(SequenceCfg { min_human_ms: 1500 }),
            withdrawal_velocity: Some(VelocityCfg {
                max_count: 5,
                window_ms: 60_000,
            }),
            limit_change_velocity: Some(VelocityCfg {
                max_count: 3,
                window_ms: 30_000,
            }),
        },
    }
}

fn session_key(id: u32) -> SessionKey {
    SessionKey {
        host: "bench.example.com".to_string(),
        ident: SessionIdent::Cookie(format!("sess_{id}")),
    }
}

/// Pre-populate store with N sessions, each having 8 events.
/// Must be called within a tokio runtime context.
fn warm_store(session_count: usize) -> (Arc<TxStore>, Arc<ArcSwap<TxVelocityConfig>>) {
    let cfg = Arc::new(ArcSwap::from_pointee(bench_config()));
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(NoopAggregator),
    ));

    // Pre-fill sessions to simulate production steady state
    for i in 0..session_count {
        let key = session_key(i as u32);
        for _ in 0..8 {
            store.record(&key, EndpointRole::Deposit, true);
        }
    }

    (store, cfg)
}

/// Bench: `TxStore::record()` for an existing session (hot path).
fn bench_record_existing_session(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();

    let (store, _cfg) = warm_store(10_000);
    let key = session_key(5_000);

    c.bench_function("tx_velocity_record_existing", |b| {
        b.iter(|| {
            store.record(black_box(&key), black_box(EndpointRole::Withdrawal), true);
        });
    });
}

/// Bench: `TxStore::record()` for a new session (cold path).
fn bench_record_new_session(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();

    let (store, _cfg) = warm_store(10_000);
    let mut counter = 100_000u32;

    c.bench_function("tx_velocity_record_new", |b| {
        b.iter(|| {
            counter += 1;
            let key = session_key(counter);
            store.record(black_box(&key), black_box(EndpointRole::Login), true);
        });
    });
}

/// Bench: `TxStore::snapshot()` retrieval (no runtime needed).
fn bench_snapshot(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();

    let (store, _cfg) = warm_store(10_000);
    let key = session_key(5_000);

    c.bench_function("tx_velocity_snapshot", |b| {
        b.iter(|| {
            black_box(store.snapshot(black_box(&key)));
        });
    });
}

/// Bench: Full record + classifier evaluation (the per-request hot path).
fn bench_full_check_path(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();

    let (store, _cfg) = warm_store(10_000);
    let key = session_key(5_000);

    c.bench_function("tx_velocity_full_check", |b| {
        b.iter(|| {
            store.record(black_box(&key), black_box(EndpointRole::Withdrawal), true);
        });
    });
}

/// Bench: Scaling with session count.
fn bench_scaling(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();

    let mut group = c.benchmark_group("tx_velocity_scaling");

    for session_count in [1_000, 5_000, 10_000, 50_000] {
        let (store, _cfg) = warm_store(session_count);
        let key = session_key((session_count / 2) as u32);

        group.bench_with_input(BenchmarkId::new("record", session_count), &session_count, |b, _| {
            b.iter(|| {
                store.record(black_box(&key), black_box(EndpointRole::Deposit), true);
            });
        });
    }

    group.finish();
}

/// Bench: Concurrent access simulation with multiple threads.
fn bench_concurrent_access(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .unwrap();
    let _guard = rt.enter();

    let (store, _cfg) = warm_store(10_000);

    c.bench_function("tx_velocity_concurrent_4threads", |b| {
        b.iter(|| {
            let handles: Vec<_> = (0..4)
                .map(|t| {
                    let store = Arc::clone(&store);
                    std::thread::spawn(move || {
                        // Each thread needs its own runtime context
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                            .unwrap();
                        let _guard = rt.enter();
                        for i in 0..100 {
                            let key = session_key(t * 1000 + i);
                            store.record(&key, EndpointRole::Withdrawal, true);
                        }
                    })
                })
                .collect();

            for h in handles {
                h.join().unwrap();
            }
        });
    });
}

criterion_group!(
    benches,
    bench_record_existing_session,
    bench_record_new_session,
    bench_snapshot,
    bench_full_check_path,
    bench_scaling,
    bench_concurrent_access,
);
criterion_main!(benches);
