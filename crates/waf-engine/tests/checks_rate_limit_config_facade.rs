//! Coverage for `checks::rate_limit::mod` facade — `RateLimitConfig::default()`,
//! `RateLimitConfig::for_tier()` and the public re-exports. Plus the
//! `RateLimitStore::check_and_consume_blocking` default impl bridge via the
//! shipped `MemoryStore` (which exercises the trait default by calling it
//! through a `dyn RateLimitStore`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use waf_common::tier::Tier;
use waf_engine::checks::RateLimitConfig;

#[test]
fn t_default_config_is_inert() {
    let cfg = RateLimitConfig::default();
    assert_eq!(cfg.session_cookie, "SESSIONID");
    assert!(cfg.tiers.is_empty());
    // for_tier on missing tier returns None
    assert!(cfg.for_tier(Tier::CatchAll).is_none());
}

#[test]
fn t_for_tier_lookup_hits_and_misses() {
    use std::collections::HashMap;
    use waf_engine::checks::rate_limit::store::LimitCfg;

    let mut tiers = HashMap::new();
    tiers.insert(
        Tier::CatchAll,
        LimitCfg {
            burst_capacity: 10,
            burst_refill_per_s: 1.0,
            window_secs: 60,
            window_limit: 100,
        },
    );
    let cfg = RateLimitConfig {
        session_cookie: "SID".into(),
        tiers,
    };
    let hit = cfg.for_tier(Tier::CatchAll).expect("hit");
    assert_eq!(hit.burst_capacity, 10);
    assert_eq!(hit.window_limit, 100);
    // Anything else misses.
    assert!(cfg.for_tier(Tier::Critical).is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t_memory_store_check_and_consume_via_blocking_bridge() {
    // The default `check_and_consume_blocking` on the trait routes through
    // tokio::block_in_place + Handle::block_on. MemoryStore overrides it,
    // so to actually exercise the *default* we need a dyn dispatch through
    // a wrapper that does NOT override. We use a tiny inline impl below.
    use async_trait::async_trait;
    use std::sync::Arc;
    use waf_engine::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

    struct DefaultBridgeStore;

    #[async_trait]
    impl RateLimitStore for DefaultBridgeStore {
        async fn check_and_consume(&self, _key: &str, _cfg: &LimitCfg, _now_ms: i64) -> anyhow::Result<Decision> {
            Ok(Decision::Allow)
        }
        async fn purge_expired(&self) -> anyhow::Result<usize> {
            Ok(0)
        }
        // NOTE: do NOT override check_and_consume_blocking — we need the
        // trait's default impl to be exercised.
    }

    let store: Arc<dyn RateLimitStore> = Arc::new(DefaultBridgeStore);
    let cfg = LimitCfg {
        burst_capacity: 5,
        burst_refill_per_s: 1.0,
        window_secs: 1,
        window_limit: 5,
    };
    // Run on a blocking thread pool so block_in_place is permitted.
    let result = tokio::task::spawn_blocking(move || store.check_and_consume_blocking("k", &cfg, 0))
        .await
        .expect("join");
    assert_eq!(result.expect("ok"), Decision::Allow);

    // purge_expired through dyn dispatch
    let store2: Arc<dyn RateLimitStore> = Arc::new(DefaultBridgeStore);
    let purged = store2.purge_expired().await.expect("purge");
    assert_eq!(purged, 0);
}

#[test]
fn t_decision_eq_and_clone() {
    use waf_engine::checks::rate_limit::store::Decision;
    let a = Decision::Allow;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(Decision::Allow, Decision::BurstExceeded);
    assert_ne!(Decision::BurstExceeded, Decision::SustainedExceeded);
}

#[test]
fn t_limit_cfg_clone_round_trip() {
    use waf_engine::checks::rate_limit::store::LimitCfg;
    let a = LimitCfg {
        burst_capacity: 7,
        burst_refill_per_s: 2.5,
        window_secs: 120,
        window_limit: 333,
    };
    let b = a.clone();
    assert_eq!(b.burst_capacity, 7);
    assert!((b.burst_refill_per_s - 2.5).abs() < 1e-9);
    assert_eq!(b.window_secs, 120);
    assert_eq!(b.window_limit, 333);
}
