// Integration tests for allow/block IP and URL endpoints + sensitive_patterns.

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
async fn allow_ip_create_list_delete() {
    let s = start_test_server().await;
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/allow-ips"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "host_code": "h1", "ip_cidr": "1.2.3.4/32", "remarks": null }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = created["data"]["id"].as_str().unwrap().to_string();

    let listed: serde_json::Value = client()
        .get(url_for(s.addr, "/api/allow-ips?host_code=h1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("list send")
        .json()
        .await
        .expect("list json");
    assert!(!listed["data"].as_array().unwrap().is_empty());

    let del = client()
        .delete(url_for(s.addr, &format!("/api/allow-ips/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(del.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn block_ip_create_list_delete() {
    let s = start_test_server().await;
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/block-ips"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "host_code": "h1", "ip_cidr": "9.9.9.9/32", "remarks": "spam" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = created["data"]["id"].as_str().unwrap().to_string();

    let resp = client()
        .delete(url_for(s.addr, &format!("/api/block-ips/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_allow_ip_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/allow-ips/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_block_ip_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/block-ips/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_url_create_list_delete() {
    let s = start_test_server().await;
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/allow-urls"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "host_code": "h1", "url_pattern": "/admin", "match_type": "exact", "remarks": null }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = created["data"]["id"].as_str().unwrap().to_string();

    let listed: serde_json::Value = client()
        .get(url_for(s.addr, "/api/allow-urls"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert!(!listed["data"].as_array().unwrap().is_empty());

    let resp = client()
        .delete(url_for(s.addr, &format!("/api/allow-urls/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn block_url_create_delete() {
    let s = start_test_server().await;
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/block-urls"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "host_code": "h1", "url_pattern": "/.env", "match_type": "exact", "remarks": null }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = created["data"]["id"].as_str().unwrap().to_string();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/block-urls/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_allow_url_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/allow-urls/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_block_url_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/block-urls/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_attack_logs_empty() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/attack-logs"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_security_events_empty() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/security-events"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_status() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], true);
    assert!(body["data"]["version"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_rules() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/reload"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_patterns_create_list_delete() {
    let s = start_test_server().await;
    let created: serde_json::Value = client()
        .post(url_for(s.addr, "/api/sensitive-patterns"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "host_code": "h1",
            "pattern": "secret123",
            "pattern_type": "literal",
            "check_request": true,
            "check_response": false,
            "action": "block",
            "remarks": null,
        }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = created["data"]["id"].as_str().unwrap().to_string();

    let resp = client()
        .get(url_for(s.addr, "/api/sensitive-patterns?host_code=h1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("list");
    assert_eq!(resp.status(), 200);

    let del = client()
        .delete(url_for(s.addr, &format!("/api/sensitive-patterns/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(del.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_sensitive_pattern_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/sensitive-patterns/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn hotlink_get_requires_host_code() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/hotlink-config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn hotlink_upsert_and_get() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/hotlink-config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "host_code": "h1",
            "enabled": true,
            "allow_empty_referer": true,
            "allowed_domains": ["example.com"],
            "redirect_url": null,
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);

    let get_resp = client()
        .get(url_for(s.addr, "/api/hotlink-config?host_code=h1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("get send");
    assert_eq!(get_resp.status(), 200);
}
