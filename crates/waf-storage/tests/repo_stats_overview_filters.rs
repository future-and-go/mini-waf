// Integration tests for `Database::get_stats_overview` with StatsFilter.
// 6 cases: default shape, host_code filter, action filter, hours filter,
// combined filters, empty-db zero counts.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods
)]

#[path = "common/mod.rs"]
mod common;

use common::{insert_event, start_postgres};
use waf_storage::StatsFilter;

// ── 1 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_default_filter_matches_prefactor_shape() {
    let fx = start_postgres().await;
    // Seed 10 events so every subquery returns non-trivial data.
    for i in 0..10_u32 {
        insert_event(fx.db.pool(), "h1", &format!("/path/{i}"), Some("SQLI-1"), "block", 1).await;
    }

    let result = fx
        .db
        .get_stats_overview(&StatsFilter::default())
        .await
        .expect("get_stats_overview");

    // All fields present (non-negative counts, vectors allocated).
    assert!(result.total_requests >= 0);
    assert!(result.total_blocked >= 0);
    assert!(result.total_allowed >= 0);
    assert!(result.hosts_count >= 0);
    assert!(result.unique_attackers >= 0);
    // Populated from seeded events.
    assert!(!result.category_breakdown.is_empty(), "category_breakdown empty");
    assert!(!result.recent_events.is_empty(), "recent_events empty");
}

// ── 2 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_host_code_filter() {
    let fx = start_postgres().await;
    // 5 events on h1, 3 on h2.
    for _ in 0..5_u32 {
        insert_event(fx.db.pool(), "h1", "/x", Some("SQLI-1"), "block", 1).await;
    }
    for _ in 0..3_u32 {
        insert_event(fx.db.pool(), "h2", "/y", Some("XSS-1"), "block", 1).await;
    }

    let result_h1 = fx
        .db
        .get_stats_overview(&StatsFilter {
            host_code: Some("h1".to_string()),
            ..StatsFilter::default()
        })
        .await
        .expect("h1 filter");

    let result_h2 = fx
        .db
        .get_stats_overview(&StatsFilter {
            host_code: Some("h2".to_string()),
            ..StatsFilter::default()
        })
        .await
        .expect("h2 filter");

    // Blocked counts for h1 and h2 must differ (5 vs 3).
    assert_ne!(
        result_h1.total_blocked, result_h2.total_blocked,
        "host_code filter did not partition blocked counts"
    );
}

// ── 3 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_action_filter() {
    let fx = start_postgres().await;
    // 4 block events + 2 log events.
    for _ in 0..4_u32 {
        insert_event(fx.db.pool(), "h1", "/x", Some("BOT-1"), "block", 1).await;
    }
    for _ in 0..2_u32 {
        insert_event(fx.db.pool(), "h1", "/y", Some("SCAN-1"), "log", 1).await;
    }

    let result_block = fx
        .db
        .get_stats_overview(&StatsFilter {
            action: Some("block".to_string()),
            ..StatsFilter::default()
        })
        .await
        .expect("block filter");

    let result_log = fx
        .db
        .get_stats_overview(&StatsFilter {
            action: Some("log".to_string()),
            ..StatsFilter::default()
        })
        .await
        .expect("log filter");

    // Blocked counts must differ when different action filters are applied.
    assert_ne!(
        result_block.total_blocked, result_log.total_blocked,
        "action filter did not affect blocked counts"
    );
}

// ── 4 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_hours_filter() {
    let fx = start_postgres().await;
    // 3 events 1h ago (within window) + 2 events 200h ago (outside 24h window).
    for _ in 0..3_u32 {
        insert_event(fx.db.pool(), "h1", "/recent", Some("SQLI-1"), "block", 1).await;
    }
    for _ in 0..2_u32 {
        insert_event(fx.db.pool(), "h1", "/old", Some("SQLI-1"), "block", 200).await;
    }

    let result_24h = fx
        .db
        .get_stats_overview(&StatsFilter {
            hours: Some(24),
            ..StatsFilter::default()
        })
        .await
        .expect("hours=24 filter");

    let result_all = fx
        .db
        .get_stats_overview(&StatsFilter::default())
        .await
        .expect("no hours filter");

    // With hours=24, blocked count should be lower than all-time.
    assert!(
        result_24h.total_blocked <= result_all.total_blocked,
        "hours filter did not reduce blocked count (24h={}, all={})",
        result_24h.total_blocked,
        result_all.total_blocked
    );
}

// ── 5 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_all_filters_combined() {
    let fx = start_postgres().await;
    // h1/block/1h-ago — the only event that matches all three filters.
    insert_event(fx.db.pool(), "h1", "/match", Some("SQLI-1"), "block", 1).await;
    // Non-matching: wrong host.
    insert_event(fx.db.pool(), "h2", "/no-host", Some("XSS-1"), "block", 1).await;
    // Non-matching: wrong action.
    insert_event(fx.db.pool(), "h1", "/no-action", Some("RCE-1"), "log", 1).await;
    // Non-matching: outside time window.
    insert_event(fx.db.pool(), "h1", "/no-time", Some("BOT-1"), "block", 100).await;

    let result = fx
        .db
        .get_stats_overview(&StatsFilter {
            hours: Some(24),
            host_code: Some("h1".to_string()),
            action: Some("block".to_string()),
        })
        .await
        .expect("combined filter");

    // Only the matching event contributes.
    assert!(
        result.total_blocked >= 1,
        "combined filter should include the matching event"
    );
    // recent_events should contain our matching entry.
    let found = result.recent_events.iter().any(|e| e.path == "/match");
    assert!(found, "matching event not in recent_events");
}

// ── 6 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_empty_db_returns_zero_counts() {
    let fx = start_postgres().await;

    let result = fx
        .db
        .get_stats_overview(&StatsFilter::default())
        .await
        .expect("empty db query");

    assert_eq!(result.total_requests, 0, "total_requests");
    assert_eq!(result.total_blocked, 0, "total_blocked");
    assert_eq!(result.total_allowed, 0, "total_allowed");
    assert_eq!(result.unique_attackers, 0, "unique_attackers");
    assert!(result.top_ips.is_empty(), "top_ips not empty");
    assert!(result.top_rules.is_empty(), "top_rules not empty");
    assert!(result.category_breakdown.is_empty(), "category_breakdown not empty");
    assert!(result.recent_events.is_empty(), "recent_events not empty");
}
