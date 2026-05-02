//! Criterion bench — FR-009 cache decision pipeline.
//!
//! Measures the three hot paths the production proxy hits per request:
//! - CRITICAL bypass (`TierGate` short-circuits at index 0)
//! - Route-rule cache hit (full chain through `RouteRuleGate`)
//! - No match → tier-default fallback (every gate runs)
//!
//! Targets (per phase-05 plan):
//!   `resolve_critical_bypass`:   p99 <  10µs
//!   `resolve_route_match_hit`:   p99 <  50µs
//!   `resolve_no_match_fallback`: p99 <  30µs
//!
//! Run with: `cargo bench -p gateway --bench cache_resolver_bench`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
use gateway::cache::{CompiledRuleSet, ResponseCache, RuleSetHolder};
use tokio::runtime::Runtime;
use waf_common::tier::{CachePolicy, Tier};

const POLICY_AGGRESSIVE_300: CachePolicy = CachePolicy::Aggressive { ttl_seconds: 300 };

fn build_cache_with_rules(n: usize) -> Arc<ResponseCache> {
    let rules: Vec<RuleDoc> = (0..n)
        .map(|i| RuleDoc {
            id: format!("r{i}"),
            match_: MatchDoc {
                host: None,
                path: PathSpec::Prefix {
                    prefix: format!("/api/v{i}/"),
                },
                methods: None,
            },
            ttl_seconds: 600,
            tags: vec![format!("tag-{i}")],
            allow_authenticated: false,
        })
        .collect();
    let set = CompiledRuleSet::try_from_doc(CacheConfigDoc {
        version: 1,
        defaults: Defaults::default(),
        rules,
    })
    .expect("compile");
    ResponseCache::with_rules(8, 60, 3600, RuleSetHolder::new(set))
}

fn resolve_critical_bypass(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let cache = build_cache_with_rules(20);
    c.bench_function("resolve_critical_bypass", |b| {
        b.iter(|| {
            rt.block_on(async {
                // CRITICAL: TierGate at index 0 short-circuits before any
                // rule walk — the entire decision is a single match arm.
                let stored = cache
                    .put(
                        ResponseCache::make_key("GET", "h", "/api/v5/x", ""),
                        black_box("h"),
                        black_box("/api/v5/x"),
                        200,
                        vec![],
                        Bytes::from_static(b"ok"),
                        Some("max-age=600"),
                        Tier::Critical,
                        &POLICY_AGGRESSIVE_300,
                        false,
                        false,
                    )
                    .await;
                debug_assert!(!stored);
                stored
            });
        });
    });
}

fn resolve_route_match_hit(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let cache = build_cache_with_rules(20);
    c.bench_function("resolve_route_match_hit", |b| {
        b.iter(|| {
            rt.block_on(async {
                // Path matches r10 → RouteRuleGate produces Cache verdict.
                let stored = cache
                    .put(
                        ResponseCache::make_key("GET", "h", "/api/v10/x", ""),
                        black_box("h"),
                        black_box("/api/v10/x"),
                        200,
                        vec![],
                        Bytes::from_static(b"ok"),
                        None,
                        Tier::Medium,
                        &POLICY_AGGRESSIVE_300,
                        false,
                        false,
                    )
                    .await;
                debug_assert!(stored);
                stored
            });
        });
    });
}

fn resolve_no_match_fallback(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let cache = build_cache_with_rules(20);
    c.bench_function("resolve_no_match_fallback", |b| {
        b.iter(|| {
            rt.block_on(async {
                // No rule matches /unknown/* → walks every gate, lands on
                // TierDefaultGate.
                let stored = cache
                    .put(
                        ResponseCache::make_key("GET", "h", "/unknown/x", ""),
                        black_box("h"),
                        black_box("/unknown/x"),
                        200,
                        vec![],
                        Bytes::from_static(b"ok"),
                        None,
                        Tier::Medium,
                        &POLICY_AGGRESSIVE_300,
                        false,
                        false,
                    )
                    .await;
                debug_assert!(stored);
                stored
            });
        });
    });
}

criterion_group!(
    benches,
    resolve_critical_bypass,
    resolve_route_match_hit,
    resolve_no_match_fallback
);
criterion_main!(benches);
