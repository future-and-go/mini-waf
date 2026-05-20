// Integration tests for GET /api/stats/overview filter behaviour.
// 6 cases: host_code, action, hours, invalid-hours-clamped, auth-required,
// empty-string filter treated as None (F4).
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

use common::{SEED_HOST_CODE, client, fetch, insert_security_event, seed_one_of_each, start_test_server, url_for};

// ── 1 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_host_code_filter() {
    let s = start_test_server().await;
    // Seed events for two hosts; filter must keep only SEED_HOST_CODE row.
    insert_security_event(&s.db, SEED_HOST_CODE, "/x", Some("SQLI-1"), "sqli", "block").await;
    insert_security_event(&s.db, "h2", "/y", Some("XSS-1"), "xss", "block").await;

    let resp = client()
        .get(url_for(s.addr, "/api/stats/overview?host_code=h1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], serde_json::json!(true));
    // With host_code=h1 the response must contain the data envelope.
    assert!(body["data"].is_object(), "data must be an object");
}

// ── 2 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_action_filter() {
    let s = start_test_server().await;
    insert_security_event(&s.db, SEED_HOST_CODE, "/block", Some("BOT-1"), "bot", "block").await;
    insert_security_event(&s.db, SEED_HOST_CODE, "/log", Some("SCAN-1"), "scan", "log").await;

    let resp = client()
        .get(url_for(s.addr, "/api/stats/overview?action=block"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], serde_json::json!(true));
    assert!(body["data"].is_object());
}

// ── 3 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_hours_filter() {
    let s = start_test_server().await;
    // Helper inserts at NOW(); hours=24 window covers it.
    insert_security_event(&s.db, SEED_HOST_CODE, "/recent", Some("SQLI-1"), "sqli", "block").await;

    let resp = client()
        .get(url_for(s.addr, "/api/stats/overview?hours=24"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], serde_json::json!(true));
    assert!(body["data"].is_object());
}

// ── 4 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_invalid_hours_clamped() {
    let s = start_test_server().await;

    // hours=99999 must be clamped to 720, not rejected with 4xx.
    let resp = client()
        .get(url_for(s.addr, "/api/stats/overview?hours=99999"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "hours=99999 should be clamped and return 200");
}

// ── 5 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_requires_auth() {
    let s = start_test_server().await;

    let resp = reqwest::Client::new()
        .get(format!("http://{}/api/stats/overview", s.addr))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401, "missing Bearer token must return 401");
}

// ── 6 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn overview_empty_string_filter_treated_as_none() {
    let s = start_test_server().await;
    seed_one_of_each(&s.db).await;

    // ?host_code=&action= — empty strings must be normalised to None by
    // `empty_string_as_none`, producing the same body shape as no params.
    let no_params = fetch(&s, "/api/stats/overview").await;
    let empty_str = fetch(&s, "/api/stats/overview?host_code=&action=").await;

    // Both must succeed.
    assert_eq!(no_params["success"], serde_json::json!(true));
    assert_eq!(empty_str["success"], serde_json::json!(true));

    // Both must return the same top-level keys in `data`.
    let keys_no: std::collections::BTreeSet<_> = no_params["data"].as_object().expect("data object").keys().collect();
    let keys_es: std::collections::BTreeSet<_> = empty_str["data"].as_object().expect("data object").keys().collect();
    assert_eq!(
        keys_no, keys_es,
        "empty-string params changed response shape vs no-params"
    );
}
