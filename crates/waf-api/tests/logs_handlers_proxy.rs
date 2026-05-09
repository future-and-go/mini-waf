// Integration tests for the VictoriaLogs proxy handlers (logs.rs).
// Uses a tiny in-process mock backend to exercise the active branches.

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

use std::net::SocketAddr;

use axum::Router;
use axum::routing::get;
use common::{client, start_test_server, start_test_server_with_logs, url_for};

/// Spin up a small mock VictoriaLogs HTTP server on a random local port.
async fn start_mock_vl() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/select/logsql/query", get(|| async { "{\"_msg\":\"ok\"}\n" }))
        .route("/select/logsql/stats_query", get(|| async { "{\"total\":1}\n" }))
        .route("/metrics", get(|| async { "vl_storage_data_size_bytes 1024\n" }))
        .route("/select/logsql/field_values", get(|| async { "block\nallow\n" }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock vl");
    let addr = listener.local_addr().expect("addr");
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (addr, task)
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_disabled_when_url_not_set() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/query?query=event_type:block"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_empty_query_400() {
    let mock_url = "http://127.0.0.1:1".to_string();
    let s = start_test_server_with_logs(mock_url).await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/query?query=%20"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_forbidden_pipe_400() {
    let mock_url = "http://127.0.0.1:1".to_string();
    let s = start_test_server_with_logs(mock_url).await;
    let resp = client()
        .get(url_for(
            s.addr,
            "/api/v1/logs/query?query=event_type%3Ablock%20%7C%20delete",
        ))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_unreachable_backend_500() {
    // Port 1 is not listening — proxy returns 500.
    let mock_url = "http://127.0.0.1:1".to_string();
    let s = start_test_server_with_logs(mock_url).await;
    let resp = client()
        .get(url_for(
            s.addr,
            "/api/v1/logs/query?query=event_type%3Ablock&start=2024-01-01T00%3A00%3A00Z&end=2024-12-31T00%3A00%3A00Z&limit=10",
        ))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 500);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_success_with_mock_backend() {
    let (mock_addr, _task) = start_mock_vl().await;
    let s = start_test_server_with_logs(format!("http://{mock_addr}")).await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/query?query=event_type%3Ablock&limit=5"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_stats_success_with_mock_backend() {
    let (mock_addr, _task) = start_mock_vl().await;
    let s = start_test_server_with_logs(format!("http://{mock_addr}")).await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/v1/logs/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["count_24h_raw"].as_str().is_some());
    assert!(body["metrics"].as_str().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_streams_success_then_cached() {
    let (mock_addr, _task) = start_mock_vl().await;
    let s = start_test_server_with_logs(format!("http://{mock_addr}")).await;
    // First call: cache miss → fetch.
    let body1: serde_json::Value = client()
        .get(url_for(s.addr, "/api/v1/logs/streams"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body1["event_type"].as_str().is_some());
    // Second call: cache hit branch.
    let body2: serde_json::Value = client()
        .get(url_for(s.addr, "/api/v1/logs/streams"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body1, body2);
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_query_disabled_returns_400_no_url() {
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
async fn logs_streams_disabled_returns_400() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/v1/logs/streams"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}
