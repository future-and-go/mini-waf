// Integration tests for /api/cache/* endpoints.

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
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn cache_stats_returns_counters() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/cache/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["hits"].is_number());
    assert!(body["misses"].is_number());
    assert!(body["hit_ratio"].is_number());
    assert!(body["backend"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_purge_tag_invalid_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cache/purge/tag"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "tag": "" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_purge_tag_too_long_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cache/purge/tag"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "tag": "x".repeat(65) }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_purge_tag_bad_chars_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cache/purge/tag"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "tag": "foo bar" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_purge_tag_ok() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cache/purge/tag"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "tag": "catalog" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_purge_route_invalid_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cache/purge/route"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "route_id": "" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_purge_route_ok() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cache/purge/route"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "route_id": "homepage" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_flush_all() {
    let s = start_test_server().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/cache"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_flush_host() {
    let s = start_test_server().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/cache/host/example.com"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_flush_key_missing_param_400() {
    let s = start_test_server().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/cache/key"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_flush_key_ok() {
    let s = start_test_server().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/cache/key?key=abc"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_backend_info() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cache/backend"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_stats_timeseries() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cache/stats/timeseries?minutes=10"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body.is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_top_routes() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cache/routes/top?limit=5"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn cache_list_tags() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/cache/tags"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["total_tags"].is_number());
    assert!(body["tags"].is_array());
}
