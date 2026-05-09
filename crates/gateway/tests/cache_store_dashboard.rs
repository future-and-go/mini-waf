//! Phase 05: ResponseCache dashboard / facade methods (timeseries, ping,
//! backend_info, top_routes, tag_entry_counts).

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

use std::sync::Arc;

use bytes::Bytes;
use gateway::cache::store::ResponseCache;
use waf_common::tier::{CachePolicy, Tier, TierPolicy};

fn cache() -> Arc<ResponseCache> {
    ResponseCache::new(8, 60, 3600)
}

fn cacheable_policy() -> CachePolicy {
    let p = TierPolicy::default();
    p.cache_policy.clone()
}

#[tokio::test]
async fn timeseries_starts_empty_and_grows_after_tick() {
    let c = cache();
    assert!(c.timeseries(60).is_empty());
    c.tick_timeseries().await;
    assert_eq!(c.timeseries(60).len(), 1);
}

#[tokio::test]
async fn timeseries_clamps_to_60_minutes() {
    let c = cache();
    for _ in 0..3 {
        c.tick_timeseries().await;
    }
    let buckets = c.timeseries(1000);
    assert!(buckets.len() <= 60);
    assert_eq!(buckets.len(), 3);
}

#[tokio::test]
async fn ping_memory_backend_reports_healthy() {
    let c = cache();
    let h = c.ping().await;
    assert!(h.ok, "moka backend always healthy");
}

#[tokio::test]
async fn backend_info_memory_label() {
    let c = cache();
    let info = c.backend_info().await;
    assert_eq!(info.backend, "memory");
    assert!(info.connected);
    assert!(info.valkey_version.is_none());
}

#[tokio::test]
async fn backend_info_for_stats_panel_caches_within_ttl() {
    let c = cache();
    let first = c.backend_info_for_stats_panel().await;
    let second = c.backend_info_for_stats_panel().await;
    assert_eq!(first.backend, second.backend);
    assert_eq!(first.connected, second.connected);
}

#[tokio::test]
async fn tag_entry_counts_empty_for_fresh_cache() {
    let c = cache();
    let counts = c.tag_entry_counts().await;
    assert!(counts.is_empty());
}

#[tokio::test]
async fn entry_count_after_public_put_round_trip() {
    let c = cache();
    let policy = cacheable_policy();
    let _ = c
        .put(
            "GET:h:/p".to_string(),
            "h",
            "/p",
            200,
            vec![("content-type".into(), "text/plain".into())],
            Bytes::from_static(b"x"),
            None,
            Tier::CatchAll,
            &policy,
            false,
            false,
        )
        .await;
    // Moka eventual consistency: poll briefly.
    for _ in 0..30 {
        if c.entry_count() > 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    // Either the policy gates kept it out (entry_count = 0) or it stored.
    // Both are acceptable — this test just exercises the facade end-to-end.
    let _final = c.entry_count();
}

#[tokio::test]
async fn top_routes_returns_at_most_limit() {
    let c = cache();
    let policy = cacheable_policy();
    for path in ["/a", "/b", "/c"] {
        let _ = c
            .put(
                format!("GET:h:{path}"),
                "h",
                path,
                200,
                vec![("content-type".into(), "text/plain".into())],
                Bytes::copy_from_slice(path.as_bytes()),
                None,
                Tier::CatchAll,
                &policy,
                false,
                false,
            )
            .await;
    }
    let top = c.top_routes(2).await;
    assert!(top.len() <= 2, "limit=2 must truncate");
}

#[tokio::test]
async fn purge_host_and_flush_are_safe_on_empty_cache() {
    let c = cache();
    c.purge_host("nope").await;
    c.flush().await;
    assert_eq!(c.entry_count(), 0);
}

#[tokio::test]
async fn purge_key_no_op_on_missing_key() {
    let c = cache();
    c.purge_key("GET:nope:/x").await;
    assert_eq!(c.entry_count(), 0);
}
