//! Integration tests for the geo restriction API.

#![allow(
    dead_code,
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::undocumented_unsafe_blocks
)]

mod common;

use serde_json::json;

use common::{TestServer, client, issue_viewer_token, start_test_server_with_tempdir_configs, url_for};

async fn create_rule(s: &TestServer, iso: &str, action: &str) -> String {
    let resp = client()
        .post(url_for(s.addr, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": iso, "action": action }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    body["data"]["id"].as_str().expect("id").to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_empty_initially() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 0);
    assert_eq!(body["data"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_list_returns_uuid_id() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let id = create_rule(&s, "vn", "block").await;
    // UUID v4 strings are 36 chars with dashes.
    assert_eq!(id.len(), 36);
    assert!(id.contains('-'));

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["iso_code"], "VN");
    assert_eq!(body["data"][0]["action"], "block");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_invalid_action() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let resp = client()
        .post(url_for(s.addr, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "us", "action": "nuke" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_requires_admin_role() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let viewer = issue_viewer_token(&s);
    let resp = client()
        .post(url_for(s.addr, "/api/geo-rules"))
        .bearer_auth(&viewer)
        .json(&json!({ "iso_code": "us", "action": "block" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_known_field_succeeds() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let id = create_rule(&s, "us", "block").await;
    let resp = client()
        .patch(url_for(s.addr, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["enabled"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_rejects_unknown_key() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let id = create_rule(&s, "us", "block").await;
    let resp = client()
        .patch(url_for(s.addr, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "CN" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_removes_rule_and_404s_on_repeat() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let id = create_rule(&s, "us", "block").await;
    let first = client()
        .delete(url_for(s.addr, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(first.status(), 200);

    let again = client()
        .delete(url_for(s.addr, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_returns_503_when_geoip_unloaded() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let resp = client()
        .post(url_for(s.addr, "/api/geoip/lookup"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ip": "8.8.8.8" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "geoip_unavailable");
    assert_eq!(body["data"]["ip"], "8.8.8.8");
}
