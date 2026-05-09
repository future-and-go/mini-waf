// Integration tests for /api/plugins and /api/tunnels.

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
async fn list_plugins_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/plugins"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["plugins"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_plugin_no_file_400() {
    let s = start_test_server().await;
    // Empty multipart with just name field — missing file.
    let form = reqwest::multipart::Form::new().text("name", "p1");
    let resp = client()
        .post(url_for(s.addr, "/api/plugins"))
        .bearer_auth(&s.admin_token)
        .multipart(form)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_plugin_no_name_400() {
    let s = start_test_server().await;
    let part = reqwest::multipart::Part::bytes(b"\0asm\x01\x00\x00\x00".to_vec()).file_name("p.wasm");
    let form = reqwest::multipart::Form::new().part("file", part);
    let resp = client()
        .post(url_for(s.addr, "/api/plugins"))
        .bearer_auth(&s.admin_token)
        .multipart(form)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn upload_plugin_bad_magic_400() {
    let s = start_test_server().await;
    let part = reqwest::multipart::Part::bytes(b"NOTAWASM".to_vec()).file_name("p.wasm");
    let form = reqwest::multipart::Form::new().text("name", "bad").part("file", part);
    let resp = client()
        .post(url_for(s.addr, "/api/plugins"))
        .bearer_auth(&s.admin_token)
        .multipart(form)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_plugin_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/plugins/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn enable_unknown_plugin_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .post(url_for(s.addr, &format!("/api/plugins/{id}/enable")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn disable_unknown_plugin_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .post(url_for(s.addr, &format!("/api/plugins/{id}/disable")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_tunnels_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["tunnels"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_tunnel_missing_name_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "target_host": "h", "target_port": 80 }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_tunnel_missing_host_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "t", "target_port": 80 }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_tunnel_invalid_port_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "t", "target_host": "h", "target_port": 0 }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_and_delete_tunnel() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/tunnels"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "t1", "target_host": "127.0.0.1", "target_port": 8081, "enabled": true }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = body["id"].as_str().unwrap().to_string();
    assert!(body["token"].as_str().unwrap().len() > 8);

    let del = client()
        .delete(url_for(s.addr, &format!("/api/tunnels/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(del.status(), 204);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_tunnel_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/tunnels/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}
