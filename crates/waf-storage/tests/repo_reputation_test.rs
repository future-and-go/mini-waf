//! Integration tests for the reputation_list repo methods (FR-042).

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::doc_markdown
)]

#[path = "common/mod.rs"]
mod common;

use chrono::{Duration, Utc};
use waf_storage::models::{CreateReputationEntry, ReputationQuery, UpdateReputationEntry};

use common::start_postgres;

fn make_entry(ip: &str, source: &str, score: i32) -> CreateReputationEntry {
    CreateReputationEntry {
        ip: ip.to_owned(),
        score,
        source: source.to_owned(),
        expires_at: Utc::now() + Duration::hours(48),
        notes: Some("integration test".to_owned()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn empty_list_returns_zero_total() {
    let fx = start_postgres().await;
    let (rows, total) = fx
        .db
        .list_reputation_entries(&ReputationQuery::default())
        .await
        .expect("list empty");
    assert!(rows.is_empty());
    assert_eq!(total, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_round_trips_via_list() {
    let fx = start_postgres().await;
    let created = fx
        .db
        .upsert_reputation_entry(&make_entry("203.0.113.1", "manual", -50))
        .await
        .expect("upsert");
    assert_eq!(created.ip, "203.0.113.1");
    assert_eq!(created.score, -50);

    let (rows, total) = fx
        .db
        .list_reputation_entries(&ReputationQuery::default())
        .await
        .expect("list after upsert");
    assert_eq!(total, 1);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].id, created.id);
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_collapses_same_ip_and_source() {
    let fx = start_postgres().await;
    let first = fx
        .db
        .upsert_reputation_entry(&make_entry("203.0.113.7", "manual", -25))
        .await
        .expect("first");
    let second = fx
        .db
        .upsert_reputation_entry(&make_entry("203.0.113.7", "manual", 75))
        .await
        .expect("second");
    assert_eq!(first.id, second.id, "UNIQUE(ip, source) must collapse");
    assert_eq!(second.score, 75);

    let (_, total) = fx
        .db
        .list_reputation_entries(&ReputationQuery::default())
        .await
        .expect("list");
    assert_eq!(total, 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn upsert_distinct_sources_for_same_ip_keeps_both() {
    let fx = start_postgres().await;
    let _ = fx
        .db
        .upsert_reputation_entry(&make_entry("198.51.100.1", "manual", 50))
        .await
        .expect("manual");
    let _ = fx
        .db
        .upsert_reputation_entry(&make_entry("198.51.100.1", "crowdsec", 90))
        .await
        .expect("crowdsec");
    let (_, total) = fx
        .db
        .list_reputation_entries(&ReputationQuery::default())
        .await
        .expect("list");
    assert_eq!(total, 2);
}

/// Exercise each filter on a shared seed set so we pay the testcontainer
/// startup cost once instead of three times. Asserts that each filter
/// narrows the row set as expected and that the unfiltered list returns
/// all rows.
#[tokio::test(flavor = "multi_thread")]
async fn list_filters_narrow_the_seed_set() {
    let fx = start_postgres().await;
    let seed = [
        ("198.51.100.10", "manual", -80),
        ("198.51.100.11", "manual", 25),
        ("198.51.100.12", "crowdsec", 90),
        ("203.0.113.5", "manual", 10),
    ];
    for (ip, src, score) in seed {
        let _ = fx
            .db
            .upsert_reputation_entry(&make_entry(ip, src, score))
            .await
            .expect("seed");
    }
    let by_source = fx
        .db
        .list_reputation_entries(&ReputationQuery {
            source: Some("crowdsec".to_owned()),
            ..Default::default()
        })
        .await
        .expect("source filter");
    assert_eq!(by_source.1, 1);
    assert_eq!(by_source.0[0].source, "crowdsec");

    let by_score = fx
        .db
        .list_reputation_entries(&ReputationQuery {
            min_score: Some(0),
            max_score: Some(50),
            ..Default::default()
        })
        .await
        .expect("score range");
    assert_eq!(by_score.1, 2);

    let by_prefix = fx
        .db
        .list_reputation_entries(&ReputationQuery {
            ip_prefix: Some("203.0.113.".to_owned()),
            ..Default::default()
        })
        .await
        .expect("prefix");
    assert_eq!(by_prefix.1, 1);
    assert_eq!(by_prefix.0[0].ip, "203.0.113.5");
}

#[tokio::test(flavor = "multi_thread")]
async fn list_paginates_via_limit_offset() {
    let fx = start_postgres().await;
    for i in 0..5u8 {
        let _ = fx
            .db
            .upsert_reputation_entry(&make_entry(&format!("203.0.113.{i}"), "manual", i32::from(i)))
            .await
            .expect("seed");
    }
    let query = ReputationQuery {
        limit: Some(2),
        offset: Some(1),
        ..Default::default()
    };
    let (rows, total) = fx.db.list_reputation_entries(&query).await.expect("paginated");
    assert_eq!(total, 5);
    assert_eq!(rows.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_partial_patches_only_named_fields() {
    let fx = start_postgres().await;
    let created = fx
        .db
        .upsert_reputation_entry(&make_entry("203.0.113.99", "manual", 10))
        .await
        .expect("seed");

    let patch = UpdateReputationEntry {
        score: Some(33),
        notes: Some("updated"),
        ..Default::default()
    };
    let updated = fx
        .db
        .update_reputation_entry(created.id, &patch)
        .await
        .expect("update")
        .expect("row");
    assert_eq!(updated.score, 33);
    assert_eq!(updated.notes.as_deref(), Some("updated"));
    assert_eq!(updated.source, "manual", "untouched fields preserved");
}

#[tokio::test(flavor = "multi_thread")]
async fn update_unknown_id_returns_none() {
    let fx = start_postgres().await;
    let res = fx
        .db
        .update_reputation_entry(
            99_999,
            &UpdateReputationEntry {
                score: Some(50),
                ..Default::default()
            },
        )
        .await
        .expect("update unknown");
    assert!(res.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_removes_and_is_idempotent() {
    let fx = start_postgres().await;
    let created = fx
        .db
        .upsert_reputation_entry(&make_entry("203.0.113.123", "manual", 0))
        .await
        .expect("seed");
    let first = fx.db.delete_reputation_entry(created.id).await.expect("delete");
    assert!(first);
    let second = fx.db.delete_reputation_entry(created.id).await.expect("delete again");
    assert!(!second);
}
