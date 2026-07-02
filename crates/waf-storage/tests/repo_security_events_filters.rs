// Time-range + tier filter coverage for list_security_events.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::field_reassign_with_default,
    clippy::similar_names,
    unused_imports
)]

#[path = "common/mod.rs"]
mod common;

use chrono::{Duration, Utc};
use common::start_postgres;
use waf_storage::models::{CreateSecurityEvent, SecurityEventQuery};

fn make_event(tier: &str) -> CreateSecurityEvent {
    CreateSecurityEvent {
        host_code: "h1".into(),
        client_ip: "1.2.3.4".into(),
        method: "GET".into(),
        path: "/x".into(),
        rule_id: None,
        rule_name: "rule".into(),
        action: "block".into(),
        detail: None,
        geo_info: None,
        waf_mode: "enforce".into(),
        tier: Some(tier.into()),
    }
}

/// Insert one row with an explicit tier and a `created_at` offset, so the
/// time-range and tier filters can be exercised against known data.
async fn insert_row(pool: &sqlx::PgPool, tier: Option<&str>, hours_ago: i64) {
    sqlx::query(
        "INSERT INTO security_events \
         (host_code, client_ip, method, path, rule_name, action, waf_mode, tier, created_at) \
         VALUES ('h1', '1.2.3.4', 'GET', '/x', 'rule', 'block', 'enforce', $1, \
                 NOW() - make_interval(hours => $2::int))",
    )
    .bind(tier)
    .bind(i32::try_from(hours_ago).unwrap())
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_writer_path_persists_tier() {
    // The production logging path flows through create_security_event_batch
    // (a separate QueryBuilder from the single insert). A column/bind desync
    // there silently drops the whole batch, so prove tier round-trips here.
    let fx = start_postgres().await;
    fx.db
        .create_security_event_batch(&[make_event("Critical"), make_event("CatchAll")])
        .await
        .unwrap();

    let (_, total_null) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some(String::new()), // no tier filter
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total_null, 2, "batch must not be silently dropped");

    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some("Critical".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(rows[0].tier.as_deref(), Some("Critical"));
}

#[tokio::test(flavor = "multi_thread")]
async fn time_range_narrows_inclusive_window() {
    let fx = start_postgres().await;
    let pool = fx.db.pool();
    insert_row(pool, Some("Critical"), 0).await; // now
    insert_row(pool, Some("High"), 2).await; // 2h ago
    insert_row(pool, Some("Medium"), 10).await; // 10h ago

    // Window [now-3h, now+1h] includes the 0h and 2h rows, excludes the 10h row.
    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            created_at_from: Some(Utc::now() - Duration::hours(3)),
            created_at_to: Some(Utc::now() + Duration::hours(1)),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2, "COUNT must match the windowed set");
    assert_eq!(rows.len(), 2);

    // No bounds → all three rows.
    let (_, total) = fx
        .db
        .list_security_events(&SecurityEventQuery::default())
        .await
        .unwrap();
    assert_eq!(total, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn tier_filter_selects_and_excludes_null() {
    let fx = start_postgres().await;
    let pool = fx.db.pool();
    insert_row(pool, Some("Critical"), 0).await;
    insert_row(pool, Some("High"), 0).await;
    insert_row(pool, Some("Medium"), 0).await;
    insert_row(pool, None, 0).await; // pre-migration NULL-tier row

    // Multi-select Critical,High.
    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some("Critical,High".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| matches!(r.tier.as_deref(), Some("Critical" | "High")))
    );

    // Single tier excludes the NULL-tier row.
    let (_, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some("Critical".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 1);

    // Empty tier behaves as no filter (not zero rows).
    let (_, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some(String::new()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 4);
}

#[tokio::test(flavor = "multi_thread")]
async fn filter_composes_with_pagination() {
    let fx = start_postgres().await;
    let pool = fx.db.pool();
    for _ in 0..5 {
        insert_row(pool, Some("Critical"), 0).await;
    }
    for _ in 0..3 {
        insert_row(pool, None, 0).await; // NULL-tier noise
    }

    // tier=Critical with a small page: total reflects the filtered set (5),
    // not the table (8); page returns page_size rows. Catches a COUNT/SELECT
    // predicate desync or an $N/LIMIT collision.
    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some("Critical".into()),
            page: Some(1),
            page_size: Some(2),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 5, "filtered COUNT, not full table");
    assert_eq!(rows.len(), 2, "page_size honored under filter (LIMIT/OFFSET intact)");

    // Last page returns the remaining row.
    let (rows, _) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            tier: Some("Critical".into()),
            page: Some(3),
            page_size: Some(2),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
}
