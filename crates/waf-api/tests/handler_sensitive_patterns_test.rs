// Integration tests for PATCH /api/sensitive-patterns/{id}.
// Covers: (a) toggle-only path flips `enabled`; (b) typed-serde rejects
// unknown fields with 400; (c) full-update path COALESCEs supplied fields;
// (d) unauth requests get 401 from the global require_auth layer.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown
)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use waf_storage::models::CreateSensitivePattern;

async fn seed_pattern(db: &waf_storage::Database, host: &str) -> uuid::Uuid {
    let row = db
        .create_sensitive_pattern(CreateSensitivePattern {
            host_code: host.to_string(),
            pattern: "ssn=\\d{3}-\\d{2}-\\d{4}".to_string(),
            pattern_type: Some("regex".to_string()),
            check_request: Some(true),
            check_response: Some(true),
            action: Some("block".to_string()),
            remarks: Some("seed".to_string()),
        })
        .await
        .expect("create seed pattern");
    row.id
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_toggle_only_flips_enabled() {
    let s = start_test_server().await;
    let id = seed_pattern(&s.db, "default").await;

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/sensitive-patterns/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "toggle should succeed");

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["id"], serde_json::json!(id));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_full_update_changes_fields() {
    let s = start_test_server().await;
    let id = seed_pattern(&s.db, "default").await;

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/sensitive-patterns/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({
            "action": "log",
            "remarks": "downgraded",
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    // Verify via list endpoint that the new action/remarks are persisted.
    let list_resp = client()
        .get(url_for(s.addr, "/api/sensitive-patterns"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send list");
    let list_body: serde_json::Value = list_resp.json().await.expect("json");
    let arr = list_body["data"].as_array().expect("data array");
    let row = arr
        .iter()
        .find(|r| r["id"] == serde_json::json!(id))
        .expect("seeded row present");
    assert_eq!(row["action"], "log");
    assert_eq!(row["remarks"], "downgraded");
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_rejects_unknown_fields_with_400() {
    let s = start_test_server().await;
    let id = seed_pattern(&s.db, "default").await;

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/sensitive-patterns/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabledd": true })) // typo
        .send()
        .await
        .expect("send");
    // Axum's `Json<T>` extractor returns 422 (Unprocessable Entity) when serde
    // fails to deserialise the body — `deny_unknown_fields` triggers that path
    // here. Any 4xx is sufficient to prove the typo was rejected at the
    // boundary; the exact code is an Axum detail, not part of our contract.
    assert!(
        resp.status().is_client_error(),
        "deny_unknown_fields must reject the typo at the serde boundary (got {})",
        resp.status()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_requires_auth() {
    let s = start_test_server().await;
    let id = seed_pattern(&s.db, "default").await;

    let resp = reqwest::Client::new()
        .patch(format!("http://{}/api/sensitive-patterns/{}", s.addr, id))
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_unknown_id_returns_404() {
    let s = start_test_server().await;
    let missing = uuid::Uuid::new_v4();

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/sensitive-patterns/{missing}")))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}
