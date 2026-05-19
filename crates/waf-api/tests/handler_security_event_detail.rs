// Integration tests for GET /api/security-events/{id}.

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
use uuid::Uuid;
use waf_storage::models::CreateSecurityEvent;

#[tokio::test(flavor = "multi_thread")]
async fn get_security_event_404_for_unknown_uuid() {
    let s = start_test_server().await;
    let unknown = Uuid::nil();
    let resp = client()
        .get(url_for(s.addr, &format!("/api/security-events/{unknown}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_security_event_4xx_for_malformed_uuid() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/security-events/not-a-uuid"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    // Axum's Path<Uuid> extractor rejects unparseable values with 4xx.
    assert!(resp.status().is_client_error(), "expected 4xx, got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_security_event_200_for_existing_event() {
    let s = start_test_server().await;
    // Seed one event so the list endpoint returns at least one row to pick an id from.
    s.db.create_security_event(CreateSecurityEvent {
        host_code: "test-host".into(),
        client_ip: "1.2.3.4".into(),
        method: "GET".into(),
        path: "/test".into(),
        rule_id: Some("SQLI-001".into()),
        rule_name: "SQL Injection".into(),
        action: "block".into(),
        detail: Some("seed".into()),
        geo_info: None,
    })
    .await
    .expect("seed event");

    let list_body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/security-events?page_size=1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send list")
        .json()
        .await
        .expect("json list");
    let id = list_body["data"][0]["id"].as_str().expect("id present");

    let resp = client()
        .get(url_for(s.addr, &format!("/api/security-events/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send detail");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json detail");
    assert_eq!(body["success"], serde_json::Value::Bool(true));
    assert_eq!(body["data"]["id"].as_str().expect("id"), id);
    assert_eq!(body["data"]["rule_id"].as_str().expect("rule_id"), "SQLI-001");
    assert_eq!(body["data"]["action"].as_str().expect("action"), "block");
}
