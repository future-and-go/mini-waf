//! Phase 05: cache stats counters, snapshot, timeseries.

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

use std::sync::atomic::Ordering;

use gateway::cache::policy::BypassReason;
use gateway::cache::stats::CacheStats;

#[test]
fn snapshot_starts_zeroed() {
    let s = CacheStats::default();
    let snap = s.snapshot();
    assert_eq!(snap.hits, 0);
    assert_eq!(snap.misses, 0);
    assert_eq!(snap.evictions, 0);
    assert_eq!(snap.stores, 0);
    assert_eq!(snap.bypassed_critical, 0);
    assert_eq!(snap.bypassed_authenticated, 0);
    assert_eq!(snap.bypassed_explicit_deny, 0);
    assert_eq!(snap.purges_tag, 0);
    assert_eq!(snap.purges_route, 0);
}

#[test]
fn record_bypass_routes_each_reason_to_correct_counter() {
    let s = CacheStats::default();
    s.record_bypass(BypassReason::CriticalTier);
    s.record_bypass(BypassReason::CriticalTier);
    s.record_bypass(BypassReason::NoCachePolicy);
    s.record_bypass(BypassReason::Authenticated);
    s.record_bypass(BypassReason::ExplicitDeny);
    // Reasons that are NOT counted by record_bypass:
    s.record_bypass(BypassReason::NonIdempotentMethod);
    s.record_bypass(BypassReason::NonCacheableStatus);
    s.record_bypass(BypassReason::SetCookie);
    s.record_bypass(BypassReason::UpstreamNoStore);
    s.record_bypass(BypassReason::UpstreamNoCache);
    s.record_bypass(BypassReason::UpstreamPrivate);
    s.record_bypass(BypassReason::NoMatch);

    let snap = s.snapshot();
    assert_eq!(snap.bypassed_critical, 3, "CriticalTier + NoCachePolicy → critical");
    assert_eq!(snap.bypassed_authenticated, 1);
    assert_eq!(snap.bypassed_explicit_deny, 1);
}

#[test]
fn manual_counters_accumulate() {
    let s = CacheStats::default();
    s.hits.fetch_add(10, Ordering::Relaxed);
    s.misses.fetch_add(5, Ordering::Relaxed);
    s.evictions.fetch_add(2, Ordering::Relaxed);
    s.stores.fetch_add(7, Ordering::Relaxed);
    s.purges_tag.fetch_add(3, Ordering::Relaxed);
    s.purges_route.fetch_add(4, Ordering::Relaxed);

    let snap = s.snapshot();
    assert_eq!(snap.hits, 10);
    assert_eq!(snap.misses, 5);
    assert_eq!(snap.evictions, 2);
    assert_eq!(snap.stores, 7);
    assert_eq!(snap.purges_tag, 3);
    assert_eq!(snap.purges_route, 4);
}

#[test]
fn hit_ratio_zero_when_no_traffic() {
    let s = CacheStats::default();
    let snap = s.snapshot();
    assert!((snap.hit_ratio() - 0.0).abs() < f64::EPSILON);
}

#[test]
fn hit_ratio_full_hits() {
    let s = CacheStats::default();
    s.hits.fetch_add(100, Ordering::Relaxed);
    let snap = s.snapshot();
    assert!((snap.hit_ratio() - 1.0).abs() < f64::EPSILON);
}

#[test]
fn hit_ratio_mixed() {
    let s = CacheStats::default();
    s.hits.fetch_add(75, Ordering::Relaxed);
    s.misses.fetch_add(25, Ordering::Relaxed);
    let snap = s.snapshot();
    assert!((snap.hit_ratio() - 0.75).abs() < 1e-9);
}

#[test]
fn route_traffic_snapshot_aggregates_hits_and_misses() {
    let s = CacheStats::default();
    s.record_route_hit("/foo");
    s.record_route_hit("/foo");
    s.record_route_hit("/bar");
    s.record_route_miss("/bar");
    s.record_route_miss("/baz");

    let map = s.route_traffic_snapshot();
    assert_eq!(map.get("/foo"), Some(&(2u64, 0u64)));
    assert_eq!(map.get("/bar"), Some(&(1u64, 1u64)));
    assert_eq!(map.get("/baz"), Some(&(0u64, 1u64)));
}

#[test]
fn route_traffic_snapshot_empty_when_no_traffic() {
    let s = CacheStats::default();
    assert!(s.route_traffic_snapshot().is_empty());
}

#[test]
fn tick_timeseries_appends_bucket() {
    let s = CacheStats::default();
    s.hits.fetch_add(3, Ordering::Relaxed);
    s.misses.fetch_add(1, Ordering::Relaxed);
    s.stores.fetch_add(2, Ordering::Relaxed);
    s.tick_timeseries(1024);
    let buckets = s.timeseries(60);
    assert_eq!(buckets.len(), 1);
    let b = &buckets[0];
    assert_eq!(b.hits, 3);
    assert_eq!(b.misses, 1);
    assert_eq!(b.stores, 2);
    assert_eq!(b.memory_used_bytes, 1024);
    assert!((b.hit_ratio - 0.75).abs() < 1e-9);
}

#[test]
fn timeseries_clamps_minutes_to_60() {
    let s = CacheStats::default();
    for _ in 0..3 {
        s.tick_timeseries(0);
    }
    // Asking for >60 still returns at most what's stored.
    let buckets = s.timeseries(1000);
    assert!(buckets.len() <= 60);
    assert_eq!(buckets.len(), 3);
}

#[test]
fn tick_timeseries_zero_traffic_yields_zero_ratio() {
    let s = CacheStats::default();
    s.tick_timeseries(0);
    let buckets = s.timeseries(60);
    assert_eq!(buckets.len(), 1);
    assert!((buckets[0].hit_ratio - 0.0).abs() < f64::EPSILON);
}

#[test]
fn tick_timeseries_records_deltas_not_cumulative() {
    let s = CacheStats::default();
    s.hits.fetch_add(10, Ordering::Relaxed);
    s.tick_timeseries(0);
    s.hits.fetch_add(5, Ordering::Relaxed);
    s.tick_timeseries(0);
    let buckets = s.timeseries(60);
    assert_eq!(buckets.len(), 2);
    assert_eq!(buckets[0].hits, 10, "first bucket = first delta");
    assert_eq!(buckets[1].hits, 5, "second bucket = delta since last tick");
}
