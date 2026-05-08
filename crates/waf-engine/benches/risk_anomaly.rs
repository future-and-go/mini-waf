//! FR-025 Phase 5 benchmark — L2 anomaly detection performance.
//!
//! Targets from phase-05 spec:
//! - L2 evaluation p99 ≤ 1ms
//! - Decay ≤ 50µs
//!
//! Groups:
//! - `anomaly_layer`: Full `AnomalyLayer.evaluate()` with all detectors
//! - `velocity_layer`: `VelocityLayer.evaluate()` sliding window + FSM
//! - `decay`: `apply_decay()` on a hot state
//! - `full_score`: `Scorer.score()` with L2 integration

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::semicolon_if_nothing_returned,
    clippy::missing_const_for_fn
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, TierPolicy};
use waf_common::{HostConfig, RequestCtx};
use waf_engine::risk::anomaly::{AnomalyCtx, AnomalyLayer};
use waf_engine::risk::config::RiskConfig;
use waf_engine::risk::decay::apply_decay;
use waf_engine::risk::key::RiskKey;
use waf_engine::risk::scorer::Scorer;
use waf_engine::risk::state::{Contributor, ContributorKind, RiskState, SeedKind};
use waf_engine::risk::store::MemoryRiskStore;
use waf_engine::risk::velocity::VelocityLayer;

fn make_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("accept".to_string(), "text/html,application/xhtml+xml".to_string());
    h.insert("accept-language".to_string(), "en-US,en;q=0.9".to_string());
    h.insert("user-agent".to_string(), "Mozilla/5.0 Chrome/120.0.0.0".to_string());
    h.insert("x-forwarded-for".to_string(), "203.0.113.1, 198.51.100.1".to_string());
    h
}

fn make_key(i: u8) -> RiskKey {
    RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)))
}

fn make_ctx() -> RequestCtx {
    RequestCtx {
        req_id: "bench-123".to_string(),
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 443,
        path: "/api/users".to_string(),
        query: String::new(),
        headers: make_headers(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: true,
        host_config: Arc::new(HostConfig {
            code: "bench".to_string(),
            host: "example.com".to_string(),
            port: 443,
            ssl: true,
            guard_status: true,
            remote_host: "backend".to_string(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: vec![],
            is_enable_load_balance: false,
            load_balance_strategy: waf_common::LoadBalanceStrategy::RoundRobin,
            defense_config: waf_common::DefenseConfig::default(),
            log_only_mode: false,
            block_page_template: None,
            preserve_host: true,
            strip_server_header: false,
            header_blocklist: vec![],
            internal_patterns: vec![],
            mask_token: "[REDACTED]".to_string(),
            body_mask_max_bytes: 1_000_000,
        }),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: Arc::new(TierPolicy {
            fail_mode: FailMode::Open,
            ddos_threshold_rps: 1000,
            cache_policy: CachePolicy::NoCache,
            risk_thresholds: RiskThresholds {
                allow: 30,
                challenge: 70,
                block: 90,
            },
        }),
        cookies: HashMap::new(),
    }
}

fn bench_anomaly_layer(c: &mut Criterion) {
    let layer = AnomalyLayer::new();
    let headers = make_headers();
    let ua = "Mozilla/5.0 Chrome/120.0.0.0";
    let xff = "203.0.113.1, 198.51.100.1";

    c.bench_function("anomaly_layer_evaluate", |b| {
        b.iter(|| {
            let ctx = AnomalyCtx::new(None, ua, Some(xff), &headers);
            black_box(layer.evaluate(&ctx, 1_000_000))
        })
    });
}

fn bench_velocity_layer(c: &mut Criterion) {
    let layer = VelocityLayer::new(1000);
    let key = make_key(1);

    c.bench_function("velocity_layer_evaluate", |b| {
        let mut ts = 1_000_000i64;
        b.iter(|| {
            ts += 1;
            black_box(layer.evaluate(&key, None, ts))
        })
    });
}

fn bench_decay(c: &mut Criterion) {
    c.bench_function("decay_apply", |b| {
        b.iter_batched(
            || {
                let mut state = RiskState::new(1000);
                state.raw_score = 80;
                state.clamped_score = 80;
                state.clean_streak = 15;
                state
            },
            |mut state| black_box(apply_decay(&mut state, 2000)),
            criterion::BatchSize::SmallInput,
        )
    });
}

fn bench_full_score(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let store = Arc::new(MemoryRiskStore::new());
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
    let scorer = Scorer::new(store, swap);
    let ctx = make_ctx();

    c.bench_function("scorer_score_with_l2", |b| {
        b.to_async(&rt).iter(|| async {
            let deltas = vec![Contributor::new(
                ContributorKind::Seed(SeedKind::Generic),
                10,
                1_000_000,
            )];
            black_box(scorer.score(&ctx, None, &deltas, None, 1_000_000).await)
        })
    });
}

criterion_group!(
    benches,
    bench_anomaly_layer,
    bench_velocity_layer,
    bench_decay,
    bench_full_score
);
criterion_main!(benches);
