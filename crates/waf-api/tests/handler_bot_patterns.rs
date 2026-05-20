// Integration tests for /api/bot-patterns endpoints.
// Covers list (builtin + custom merge), create validation, toggle for both
// builtin (rule_overrides upsert) and custom (bot_patterns UPDATE) ids,
// plus the unhappy paths (empty pattern, empty name, malformed custom id,
// missing custom id).
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

// ── 1: GET list returns builtin patterns even with empty custom table ───────

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_builtin_patterns_when_db_empty() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    let patterns = body["patterns"].as_array().expect("patterns array");
    assert!(!patterns.is_empty(), "builtin BOT-* rules should always appear");
    let any_builtin = patterns
        .iter()
        .any(|p| p["id"].as_str().is_some_and(|id| id.starts_with("BOT-")));
    assert!(any_builtin, "at least one BOT-* rule expected");
}

// ── 2: GET list requires JWT ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn list_requires_auth() {
    let s = start_test_server().await;
    let resp = reqwest::Client::new()
        .get(format!("http://{}/api/bot-patterns", s.addr))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

// ── 3: POST creates a custom pattern and surfaces it in subsequent list ─────

#[tokio::test(flavor = "multi_thread")]
async fn create_then_list_includes_custom_row() {
    let s = start_test_server().await;
    let payload = serde_json::json!({
        "name": "block-curl",
        "pattern": "(?i)curl",
        "action": "block",
        "description": "Block curl UA",
        "tags": ["test"],
    });
    let resp = client()
        .post(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .json(&payload)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], serde_json::json!(true));
    let new_id = body["data"]["id"].as_str().expect("id");
    assert!(new_id.starts_with("custom-"), "id must be custom-prefixed");

    // List should now contain the custom row.
    let list: serde_json::Value = client()
        .get(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("json list");
    let patterns = list["patterns"].as_array().expect("array");
    assert!(
        patterns.iter().any(|p| p["id"].as_str() == Some(new_id)),
        "newly created custom row should appear in list"
    );
}

// ── 4: POST rejects empty pattern ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_empty_pattern() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "name": "x", "pattern": "   " }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

// ── 5: POST rejects empty name ──────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_empty_name() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "name": "", "pattern": "ua-x" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

// ── 6: PATCH toggle on a builtin id upserts rule_overrides ──────────────────

#[tokio::test(flavor = "multi_thread")]
async fn toggle_builtin_id_writes_rule_overrides() {
    let s = start_test_server().await;
    // Pick the first builtin id surfaced by the list endpoint to avoid
    // hard-coding ids that may change as new builtin patterns ship.
    let list: serde_json::Value = client()
        .get(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let builtin_id = list["patterns"]
        .as_array()
        .expect("array")
        .iter()
        .filter_map(|p| p["id"].as_str())
        .find(|id| id.starts_with("BOT-"))
        .expect("builtin id")
        .to_string();

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/bot-patterns/{builtin_id}")))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    // List again — the toggled builtin must now be disabled.
    let after: serde_json::Value = client()
        .get(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let row = after["patterns"]
        .as_array()
        .expect("array")
        .iter()
        .find(|p| p["id"].as_str() == Some(&builtin_id))
        .expect("toggled row");
    assert_eq!(row["enabled"], serde_json::json!(false));
}

// ── 7: PATCH toggle on a custom id updates the bot_patterns row ─────────────

#[tokio::test(flavor = "multi_thread")]
async fn toggle_custom_id_updates_row() {
    let s = start_test_server().await;
    // Seed a custom row via POST.
    let create: serde_json::Value = client()
        .post(url_for(s.addr, "/api/bot-patterns"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "name": "toggle-target", "pattern": "ua-y" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = create["data"]["id"].as_str().expect("id").to_string();

    let resp = client()
        .patch(url_for(s.addr, &format!("/api/bot-patterns/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

// ── 8: PATCH custom-{garbage} returns 404 ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn toggle_malformed_custom_id_returns_404() {
    let s = start_test_server().await;
    let resp = client()
        .patch(url_for(s.addr, "/api/bot-patterns/custom-not-an-int"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

// ── 9: PATCH missing custom id returns 404 ──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn toggle_missing_custom_id_returns_404() {
    let s = start_test_server().await;
    let resp = client()
        .patch(url_for(s.addr, "/api/bot-patterns/custom-9999999"))
        .bearer_auth(&s.admin_token)
        .json(&serde_json::json!({ "enabled": true }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}
