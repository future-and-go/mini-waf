// Integration tests for GET /api/stats/endpoints.
// 7 cases: happy path, empty db, clamp-low, clamp-high, auth-required,
// filter by host_code, filter by action.
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
async fn endpoints_happy_path() {
    let s = start_test_server().await;
    seed_one_of_each(&s.db).await;

    let body = fetch(&s, "/api/stats/endpoints").await;
    assert_eq!(body["success"], serde_json::json!(true));
    assert!(body["data"]["cells"].is_array(), "data.cells must be array");
    assert!(
        body["data"]["metadata"]["total_events"].is_number(),
        "data.metadata.total_events must be a number"
    );
}

// ── 2 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_empty_db() {
    let s = start_test_server().await;

    let body = fetch(&s, "/api/stats/endpoints").await;
    assert_eq!(body["success"], serde_json::json!(true));
    assert_eq!(body["data"]["cells"], serde_json::json!([]));
    assert_eq!(body["data"]["metadata"]["total_events"], serde_json::json!(0));
}

// ── 3 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_clamps_hours_low() {
    let s = start_test_server().await;

    // hours=0 should be treated as 1 (clamped), not rejected.
    let resp = client()
        .get(url_for(s.addr, "/api/stats/endpoints?hours=0"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "hours=0 should return 200 (clamped to 1)");
}

// ── 4 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_clamps_hours_high() {
    let s = start_test_server().await;

    // hours=99999 should be treated as 720 (clamped), not rejected.
    let resp = client()
        .get(url_for(s.addr, "/api/stats/endpoints?hours=99999"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200, "hours=99999 should return 200 (clamped to 720)");
}

// ── 5 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_requires_auth() {
    let s = start_test_server().await;

    let resp = reqwest::Client::new()
        .get(format!("http://{}/api/stats/endpoints", s.addr))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401, "missing Bearer token must return 401");
}

// ── 6 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_filter_by_host_code() {
    let s = start_test_server().await;

    // Seed one security_event on SEED_HOST_CODE and one on a distinct host.
    insert_security_event(&s.db, SEED_HOST_CODE, "/h1-path", Some("SQLI-1"), "sqli", "block").await;
    insert_security_event(&s.db, "h2", "/h2-path", Some("XSS-1"), "xss", "block").await;

    let url = format!("/api/stats/endpoints?host_code={SEED_HOST_CODE}");
    let body = fetch(&s, &url).await;
    assert_eq!(body["success"], serde_json::json!(true));

    let cells = body["data"]["cells"].as_array().expect("cells array");
    // Only the seeded host's paths should appear; the other host must be absent.
    for cell in cells {
        assert_ne!(cell["path"], "/h2-path", "h2 path leaked into filtered result");
    }
    let has_h1 = cells.iter().any(|c| c["path"] == "/h1-path");
    assert!(has_h1, "seeded host path not found with host_code filter");
}

// ── 7 ──────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn endpoints_filter_by_action() {
    let s = start_test_server().await;

    // One block event, one log event — same host so the only differing axis
    // is the action filter.
    insert_security_event(&s.db, SEED_HOST_CODE, "/block-path", Some("BOT-1"), "bot", "block").await;
    insert_security_event(&s.db, SEED_HOST_CODE, "/log-path", Some("SCAN-1"), "scan", "log").await;

    let body = fetch(&s, "/api/stats/endpoints?action=block").await;
    assert_eq!(body["success"], serde_json::json!(true));

    let cells = body["data"]["cells"].as_array().expect("cells array");
    for cell in cells {
        assert_ne!(cell["path"], "/log-path", "log path leaked into block filter");
    }
    let has_block = cells.iter().any(|c| c["path"] == "/block-path");
    assert!(has_block, "block path not found with action=block filter");
}
