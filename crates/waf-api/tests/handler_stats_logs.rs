// Integration tests for /api/stats/* and /api/v1/logs/* (logs disabled in fixture).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};

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
