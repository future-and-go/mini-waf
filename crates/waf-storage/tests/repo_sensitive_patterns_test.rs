// Integration tests for the new sensitive-pattern mutation methods
// `toggle_sensitive_pattern` and `update_sensitive_pattern`.
// Covers: toggle flips enabled; toggle returns false on missing id; update
// COALESCEs (None columns preserved, Some columns overwrite); update returns
// None on missing id.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods
)]

#[path = "common/mod.rs"]
mod common;

use common::start_postgres;
use waf_storage::models::{CreateSensitivePattern, UpdateSensitivePattern};

async fn seed(db: &waf_storage::Database) -> uuid::Uuid {
    db.create_sensitive_pattern(CreateSensitivePattern {
        host_code: "default".to_string(),
        pattern: "card=\\d{16}".to_string(),
        pattern_type: Some("regex".to_string()),
        check_request: Some(true),
        check_response: Some(false),
        action: Some("block".to_string()),
        remarks: Some("seed".to_string()),
    })
    .await
    .expect("seed")
    .id
}

#[tokio::test(flavor = "multi_thread")]
async fn toggle_flips_enabled_and_returns_true() {
    let fx = start_postgres().await;
    let id = seed(&fx.db).await;

    let ok = fx.db.toggle_sensitive_pattern(id, false).await.expect("toggle");
    assert!(ok, "row exists, toggle should report true");

    // `list_sensitive_patterns` filters to enabled rows only, so after flipping
    // to false the row should no longer appear in the listing.
    let rows = fx.db.list_sensitive_patterns(Some("default")).await.expect("list");
    assert!(
        rows.iter().all(|r| r.id != id),
        "toggled-off row must be filtered out of enabled-only listing"
    );

    // Round-trip by flipping back to verify the update affected this id.
    let ok2 = fx.db.toggle_sensitive_pattern(id, true).await.expect("toggle back");
    assert!(ok2);
    let rows2 = fx.db.list_sensitive_patterns(Some("default")).await.expect("list");
    let row = rows2.iter().find(|r| r.id == id).expect("row present after re-enable");
    assert!(row.enabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn toggle_missing_returns_false() {
    let fx = start_postgres().await;
    let ok = fx
        .db
        .toggle_sensitive_pattern(uuid::Uuid::new_v4(), true)
        .await
        .expect("toggle");
    assert!(!ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_coalesces_none_fields() {
    let fx = start_postgres().await;
    let id = seed(&fx.db).await;

    // Only `action` is supplied; all other columns must retain their seed value.
    let updated = fx
        .db
        .update_sensitive_pattern(
            id,
            UpdateSensitivePattern {
                action: Some("log"),
                ..Default::default()
            },
        )
        .await
        .expect("update")
        .expect("row exists");

    assert_eq!(updated.action, "log", "supplied column overwritten");
    assert_eq!(updated.pattern, "card=\\d{16}", "untouched column preserved");
    assert_eq!(updated.remarks.as_deref(), Some("seed"), "remarks preserved");
    assert!(updated.check_request, "check_request preserved");
}

#[tokio::test(flavor = "multi_thread")]
async fn update_missing_returns_none() {
    let fx = start_postgres().await;
    let res = fx
        .db
        .update_sensitive_pattern(
            uuid::Uuid::new_v4(),
            UpdateSensitivePattern {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .await
        .expect("update call");
    assert!(res.is_none());
}
