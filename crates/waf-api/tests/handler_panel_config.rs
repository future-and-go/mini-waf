// Integration tests for /api/panel-config — disabled when panel_config_path is None.

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

use common::{client, start_test_server, start_test_server_with_panel, url_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn get_panel_config_400_when_disabled() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/panel-config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["error"].as_str().unwrap().contains("panel.config_path"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_panel_config_400_when_disabled() {
    let s = start_test_server().await;
    let resp = client()
        .put(url_for(s.addr, "/api/panel-config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({}))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_panel_config_ok_when_enabled() {
    let (s, _path) = start_test_server_with_panel().await;
    let resp = client()
        .get(url_for(s.addr, "/api/panel-config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], true);
    assert!(body["data"]["config"].is_object());
    assert!(body["data"]["revision"].is_number());
}

#[tokio::test(flavor = "multi_thread")]
async fn put_panel_config_ok_when_enabled() {
    let (s, _path) = start_test_server_with_panel().await;
    // Round-trip the default config back through PUT.
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/panel-config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("get")
        .json()
        .await
        .expect("json");
    let cfg = body["data"]["config"].clone();

    let put = client()
        .put(url_for(s.addr, "/api/panel-config"))
        .bearer_auth(&s.admin_token)
        .json(&cfg)
        .send()
        .await
        .expect("put");
    assert_eq!(put.status(), 200);
}
