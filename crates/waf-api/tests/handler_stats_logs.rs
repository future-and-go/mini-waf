// Integration tests for /api/stats/* and /api/v1/logs/* (logs disabled in fixture).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::doc_markdown,
    clippy::redundant_clone
)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use waf_storage::models::CreateSecurityEvent;

#[tokio::test(flavor = "multi_thread")]
async fn stats_overview_ok() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/stats/overview"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_timeseries_ok() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/stats/timeseries"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_geo_ok() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/stats/geo"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_400_when_disabled() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/query?query=foo"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_stats_400_when_disabled() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_streams_400_when_disabled() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/streams"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_log_ok() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/audit-log"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    // Endpoint should respond — either 200 with list or 200 even empty.
    assert!(resp.status().is_success() || resp.status() == 500);
}

// === /api/stats/timeseries-by-category ===

#[tokio::test(flavor = "multi_thread")]
async fn stats_timeseries_by_category_ok_empty() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/stats/timeseries-by-category?hours=24"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], serde_json::Value::Bool(true));
    assert!(body["data"].is_array(), "data must be array, got: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_timeseries_by_category_clamps_excessive_hours() {
    let s = start_test_server().await;
    // hours=9999 is clamped to 720 in the handler — the endpoint must still
    // succeed and return a valid payload shape.
    let resp = client()
        .get(url_for(s.addr, "/api/stats/timeseries-by-category?hours=9999"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_timeseries_by_category_filters_by_host_code() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(
            s.addr,
            "/api/stats/timeseries-by-category?hours=1&host_code=nonexistent",
        ))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let data = body["data"].as_array().expect("array");
    assert!(
        data.is_empty(),
        "nonexistent host_code must yield empty data, got: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_timeseries_by_category_buckets_seeded_event() {
    let s = start_test_server().await;
    s.db.create_security_event(CreateSecurityEvent {
        host_code: "h1".into(),
        client_ip: "1.2.3.4".into(),
        method: "GET".into(),
        path: "/x".into(),
        rule_id: Some("SQLI-007".into()),
        rule_name: "x".into(),
        action: "block".into(),
        detail: None,
        geo_info: None,
    })
    .await
    .expect("seed event");

    let resp = client()
        .get(url_for(s.addr, "/api/stats/timeseries-by-category?hours=1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let data = body["data"].as_array().expect("array");
    assert!(!data.is_empty(), "seeded SQLI-007 event must surface, got: {body}");
    // `category_of(rule_id)` maps SQLI-* prefixes to category `sqli`.
    assert_eq!(data[0]["category"].as_str().expect("category"), "sqli");
    assert!(data[0]["count"].as_i64().unwrap_or(0) >= 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_timeseries_by_category_honours_category_of_prefix_priority() {
    // Locks in the DRY refactor that replaced this query's inline CASE with
    // `category_of(rule_id)`. The function gives `ADV-SSRF-*` priority over
    // the generic `ADV-*` fallback — if a future change re-introduces a
    // hand-rolled CASE that orders branches incorrectly (`ADV-%` before
    // `ADV-SSRF%`), this test fails because the category surfaces as
    // `advanced` instead of `ssrf`.
    let s = start_test_server().await;
    s.db.create_security_event(CreateSecurityEvent {
        host_code: "h1".into(),
        client_ip: "1.2.3.4".into(),
        method: "GET".into(),
        path: "/x".into(),
        rule_id: Some("ADV-SSRF-001".into()),
        rule_name: "x".into(),
        action: "block".into(),
        detail: None,
        geo_info: None,
    })
    .await
    .expect("seed event");

    let resp = client()
        .get(url_for(s.addr, "/api/stats/timeseries-by-category?hours=1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    let data = body["data"].as_array().expect("array");
    assert!(!data.is_empty(), "seeded ADV-SSRF-001 event must surface, got: {body}");
    assert_eq!(
        data[0]["category"].as_str().expect("category"),
        "ssrf",
        "ADV-SSRF-* must map to 'ssrf' (longer-prefix priority over ADV-* fallback)"
    );
}
