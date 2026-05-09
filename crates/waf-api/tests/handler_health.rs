// Integration tests for /health endpoint.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};

#[tokio::test(flavor = "multi_thread")]
async fn health_returns_ok_with_components() {
    let s = start_test_server().await;
    let resp = client().get(url_for(s.addr, "/health")).send().await.expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["components"]["database"], "ok");
    assert_eq!(body["components"]["waf_engine"], "ok");
    assert!(body["components"]["plugins"]["loaded"].is_number());
    assert!(body["components"]["tunnels"]["configured"].is_number());
    assert!(body["components"]["cache"]["entries"].is_number());
    assert!(body["counters"]["total_requests"].is_number());
    assert!(body["counters"]["total_blocked"].is_number());
    assert!(body["version"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn health_does_not_require_auth() {
    let s = start_test_server().await;
    let resp = client().get(url_for(s.addr, "/health")).send().await.expect("send");
    assert_eq!(resp.status(), 200);
}
