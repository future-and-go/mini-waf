//! Criterion bench — FR-009 Phase 4 tag purge throughput.
//!
//! Two micro-benches:
//! - `put_with_5_tags`:    insert path through `TagIndex::register` (5 tags/key)
//! - `purge_by_tag_10k`:   purge a single tag holding 10k keys
//!
//! Targets (per phase-05 plan):
//!   `put_with_5_tags`:       p99 < 5µs
//!   `purge_by_tag_10k_keys`: < 50ms
//!
//! Run with: `cargo bench -p gateway --bench cache_purge_bench`

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use bytes::Bytes;
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use gateway::cache::config::{CacheConfigDoc, Defaults, MatchDoc, PathSpec, RuleDoc};
use gateway::cache::{CompiledRuleSet, ResponseCache, RuleSetHolder};
use tokio::runtime::Runtime;
use waf_common::tier::{CachePolicy, Tier};

const POLICY_AGGRESSIVE_300: CachePolicy = CachePolicy::Aggressive { ttl_seconds: 300 };

/// Build a cache where `/p` matches a rule with the given tags. `RouteRuleGate`
/// auto-prepends `rule.id`, so total tags-per-entry = `1 + tags.len()`.
fn cache_with_n_tags(n_tags: usize) -> Arc<ResponseCache> {
    let tags: Vec<String> = (0..n_tags).map(|i| format!("t{i}")).collect();
    let set = CompiledRuleSet::try_from_doc(CacheConfigDoc {
        version: 1,
        defaults: Defaults::default(),
        rules: vec![RuleDoc {
            id: "r".into(),
            match_: MatchDoc {
                host: None,
                path: PathSpec::Prefix { prefix: "/p".into() },
                methods: None,
            },
            ttl_seconds: 600,
            tags,
            allow_authenticated: false,
        }],
    })
    .expect("compile");
    // Capacity high enough that 10k keys all fit.
    ResponseCache::with_rules(1024, 60, 3600, RuleSetHolder::new(set))
}

fn put_with_5_tags(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    let cache = cache_with_n_tags(4); // 4 + 1 (auto rule.id) = 5 tags
    let mut counter: u64 = 0;
    c.bench_function("put_with_5_tags", |b| {
        b.iter(|| {
            counter = counter.wrapping_add(1);
            let path = format!("/p/{counter}");
            rt.block_on(async {
                let stored = cache
                    .put(
                        ResponseCache::make_key("GET", "h", &path, ""),
                        black_box("h"),
                        black_box(path.as_str()),
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

fn purge_by_tag_10k_keys(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();
    c.bench_function("purge_by_tag_10k_keys", |b| {
        // Per-iteration setup: re-seed 10k keys (purge consumes them).
        // `iter_batched_ref` would be cleaner, but the closure must be sync and
        // the put path is async — so do setup + measurement inside `iter`.
        b.iter(|| {
            let cache = cache_with_n_tags(1); // 1 + auto = 2 tags
            rt.block_on(async {
                for i in 0..10_000u32 {
                    let path = format!("/p/{i}");
                    let _ = cache
                        .put(
                            ResponseCache::make_key("GET", "h", &path, ""),
                            "h",
                            path.as_str(),
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
                }
                // Measurement target: this single call.
                let n = cache.purge_by_tag(black_box("t0")).await;
                debug_assert_eq!(n, 10_000);
                n
            })
        });
    });
}

criterion_group!(benches, put_with_5_tags, purge_by_tag_10k_keys);
criterion_main!(benches);
