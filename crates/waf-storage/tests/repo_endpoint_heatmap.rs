// Integration tests for `Database::get_endpoint_heatmap`.
// 13 test cases covering: empty, single, multi, filters (host/action/hours),
// top-20 truncation, NULL exclusion, metadata counts, 'other' rollup,
// sum invariant, path truncation, and make_interval smoke.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

#[path = "common/mod.rs"]
mod common;

use common::{insert_event, start_postgres};
use waf_storage::HeatmapFilter;

// ── 1 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_empty_db() {
    let fx = start_postgres().await;
    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");
    assert!(result.cells.is_empty());
    assert_eq!(result.total_events, 0);
}

// ── 2 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_single_event() {
    let fx = start_postgres().await;
    insert_event(fx.db.pool(), "h1", "/a", Some("SQLI-1"), "block", 1).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].path, "/a");
    assert_eq!(result.cells[0].category, "sqli");
    assert_eq!(result.cells[0].count, 1);
    assert_eq!(result.total_events, 1);
}

// ── 3 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_multi_path_multi_cat() {
    let fx = start_postgres().await;
    // 5 paths × 3 categories with varying counts
    let paths = ["/p1", "/p2", "/p3", "/p4", "/p5"];
    let rules = [("SQLI-1", 2_i64), ("XSS-1", 3), ("RCE-1", 1)];
    for path in &paths {
        for (rule, count) in &rules {
            for _ in 0..*count {
                insert_event(fx.db.pool(), "h1", path, Some(rule), "block", 1).await;
            }
        }
    }

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    // Each (path, category) pair that had events should appear as a cell.
    assert!(!result.cells.is_empty());
    // All returned cells should have non-zero count.
    for cell in &result.cells {
        assert!(cell.count > 0, "zero-count cell: {cell:?}");
    }
    // total_events == sum of cell counts (invariant).
    let sum: i64 = result.cells.iter().map(|c| c.count).sum();
    assert_eq!(result.total_events, sum);
}

// ── 4 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_filters_by_host_code() {
    let fx = start_postgres().await;
    insert_event(fx.db.pool(), "h1", "/a", Some("SQLI-1"), "block", 1).await;
    insert_event(fx.db.pool(), "h2", "/b", Some("XSS-1"), "block", 1).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: Some("h1".to_string()),
            action: None,
        })
        .await
        .expect("query");

    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].path, "/a");
}

// ── 5 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_filters_by_action() {
    let fx = start_postgres().await;
    insert_event(fx.db.pool(), "h1", "/a", Some("SQLI-1"), "block", 1).await;
    insert_event(fx.db.pool(), "h1", "/b", Some("XSS-1"), "log", 1).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: Some("block".to_string()),
        })
        .await
        .expect("query");

    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].path, "/a");
}

// ── 6 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_filters_by_hours_window() {
    let fx = start_postgres().await;
    insert_event(fx.db.pool(), "h1", "/recent", Some("SQLI-1"), "block", 1).await;
    insert_event(fx.db.pool(), "h1", "/old", Some("XSS-1"), "block", 100).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    // Only the event 1h ago should be within the 24h window.
    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].path, "/recent");
}

// ── 7 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_top20_truncation() {
    let fx = start_postgres().await;
    // 30 distinct paths, 1 event each.
    for i in 0..30_u32 {
        insert_event(fx.db.pool(), "h1", &format!("/path/{i:02}"), Some("SQLI-1"), "block", 1).await;
    }

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    // At most 20 distinct paths in the result.
    let distinct_paths: std::collections::HashSet<_> = result.cells.iter().map(|c| c.path.as_str()).collect();
    assert!(
        distinct_paths.len() <= 20,
        "expected ≤20 paths, got {}",
        distinct_paths.len()
    );
    assert_eq!(
        result.paths_sampled,
        i64::try_from(distinct_paths.len()).unwrap_or(i64::MAX)
    );
}

// ── 8 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_excludes_null_rule_id() {
    let fx = start_postgres().await;
    // NULL rule_id — must be excluded by AND rule_id IS NOT NULL.
    insert_event(fx.db.pool(), "h1", "/null-rule", None, "block", 1).await;
    // Non-null rule_id — must appear.
    insert_event(fx.db.pool(), "h1", "/sqli", Some("SQLI-1"), "block", 1).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    // Only the SQLI cell should be present.
    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].path, "/sqli");
    assert_eq!(result.cells[0].category, "sqli");
}

// ── 9 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_metadata_counts() {
    let fx = start_postgres().await;
    // 4 paths × 2 categories × 5 events each = 40 total events.
    let paths = ["/m1", "/m2", "/m3", "/m4"];
    let rules = ["SQLI-1", "XSS-1"];
    for path in &paths {
        for rule in &rules {
            for _ in 0..5_u32 {
                insert_event(fx.db.pool(), "h1", path, Some(rule), "block", 1).await;
            }
        }
    }

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    assert_eq!(result.paths_sampled, 4, "paths_sampled");
    assert_eq!(result.categories_total, 2, "categories_total");
    assert_eq!(result.total_events, 40, "total_events");
}

// ── 10 ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_other_rollup_when_more_than_12_categories() {
    let fx = start_postgres().await;
    // 13 distinct categories on a single path.
    let rules = [
        "SQLI-1",
        "XSS-1",
        "RCE-1",
        "TRAV-1",
        "SCAN-1",
        "BOT-1",
        "CC-1",
        "ADV-SSRF-1",
        "ADV-SSTI-1",
        "ADV-1",
        "CRS-RESP-1",
        "CRS-1",
        "CVE-2024-1",
    ];
    for rule in &rules {
        insert_event(fx.db.pool(), "h1", "/target", Some(rule), "block", 1).await;
    }

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    // At least one cell must be labeled 'other' (13th+ category rolled up).
    let has_other = result.cells.iter().any(|c| c.category == "other");
    assert!(has_other, "'other' rollup cell missing with 13 categories");

    // No data lost: sum of cell counts equals total_events.
    let sum: i64 = result.cells.iter().map(|c| c.count).sum();
    assert_eq!(result.total_events, sum, "total_events invariant broken");
}

// ── 11 ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_total_events_equals_sum_of_cells() {
    let fx = start_postgres().await;
    // Mixed paths and categories.
    for i in 0..5_u32 {
        for _ in 0..3_u32 {
            insert_event(fx.db.pool(), "h1", &format!("/chk/{i}"), Some("BOT-1"), "log", 2).await;
        }
    }

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    let sum: i64 = result.cells.iter().map(|c| c.count).sum();
    assert_eq!(
        result.total_events, sum,
        "total_events ({}) != sum of cells ({})",
        result.total_events, sum
    );
}

// ── 12 ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_truncates_path_to_256_chars() {
    let fx = start_postgres().await;
    // 400-char path — query uses LEFT(path, 256).
    let long_path = "/x".repeat(200); // 400 chars
    insert_event(fx.db.pool(), "h1", &long_path, Some("SQLI-1"), "block", 1).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("query");

    assert_eq!(result.cells.len(), 1);
    assert!(
        result.cells[0].path.len() <= 256,
        "path not truncated: len={}",
        result.cells[0].path.len()
    );
}

// ── 13 ─────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn heatmap_window_uses_make_interval_smoke() {
    let fx = start_postgres().await;
    // Event inserted at ~24h ago boundary; verifies make_interval(hours => 24)
    // is accepted by Postgres without panic / type error.
    insert_event(fx.db.pool(), "h1", "/boundary", Some("GEO-VN"), "log", 23).await;

    let result = fx
        .db
        .get_endpoint_heatmap(&HeatmapFilter {
            hours: 24,
            host_code: None,
            action: None,
        })
        .await
        .expect("make_interval smoke");

    // The event at 23h ago must be within the 24h window.
    assert_eq!(result.cells.len(), 1);
    assert_eq!(result.cells[0].path, "/boundary");
}
