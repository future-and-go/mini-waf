// Integration tests for /api/hosts CRUD.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use serde_json::json;

fn host_payload(host: &str) -> serde_json::Value {
    json!({
        "host": host,
        "port": 8080,
        "ssl": false,
        "guard_status": true,
        "remote_host": "127.0.0.1",
        "remote_port": 9090,
        "remote_ip": null,
        "cert_file": null,
        "key_file": null,
        "remarks": null,
        "start_status": true,
        "log_only_mode": false,
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn list_hosts_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/hosts"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], true);
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_get_update_delete_host() {
    let s = start_test_server().await;
    // Create
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/hosts"))
        .bearer_auth(&s.admin_token)
        .json(&host_payload("example.com"))
        .send()
        .await
        .expect("create send")
        .json()
        .await
        .expect("create json");
    let host_id = created["data"]["id"].as_str().unwrap().to_string();

    // Get
    let got: serde_json::Value = client()
        .get(url_for(s.addr, &format!("/api/hosts/{host_id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("get send")
        .json()
        .await
        .expect("get json");
    assert_eq!(got["data"]["host"], "example.com");

    // Update
    let upd_resp = client()
        .put(url_for(s.addr, &format!("/api/hosts/{host_id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "guard_status": false }))
        .send()
        .await
        .expect("update send");
    assert_eq!(upd_resp.status(), 200);

    // Delete
    let del = client()
        .delete(url_for(s.addr, &format!("/api/hosts/{host_id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del send");
    assert_eq!(del.status(), 200);

    // Get again — 404
    let r404 = client()
        .get(url_for(s.addr, &format!("/api/hosts/{host_id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("get again");
    assert_eq!(r404.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_host_invalid_port_400() {
    let s = start_test_server().await;
    let mut payload = host_payload("badport.com");
    payload["port"] = json!(0);
    let resp = client()
        .post(url_for(s.addr, "/api/hosts"))
        .bearer_auth(&s.admin_token)
        .json(&payload)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["error"].as_str().unwrap().contains("port"));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_host_invalid_remote_port_400() {
    let s = start_test_server().await;
    let mut payload = host_payload("badrport.com");
    payload["remote_port"] = json!(70_000);
    let resp = client()
        .post(url_for(s.addr, "/api/hosts"))
        .bearer_auth(&s.admin_token)
        .json(&payload)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_host_invalid_port_400() {
    let s = start_test_server().await;
    // Create a real host first
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/hosts"))
        .bearer_auth(&s.admin_token)
        .json(&host_payload("upd.com"))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = created["data"]["id"].as_str().unwrap();
    let resp = client()
        .put(url_for(s.addr, &format!("/api/hosts/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "port": 0 }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_unknown_host_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .put(url_for(s.addr, &format!("/api/hosts/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ssl": true }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_host_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/hosts/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_unknown_host_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .get(url_for(s.addr, &format!("/api/hosts/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}
