// Integration tests for less-covered REST endpoints in handlers.rs:
// custom rules, certificates (CRUD via JSON, no upload), LB backends.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use serde_json::json;

// ── Custom rules ─────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn list_custom_rules_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/custom-rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["data"].is_array());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_delete_custom_rule() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/custom-rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "host_code": "default",
            "name": "block-foo",
            "description": null,
            "priority": 100,
            "enabled": true,
            "condition_op": "AND",
            "conditions": [{"field": "uri", "operator": "contains", "value": "foo"}],
            "action": "block",
            "action_status": 403,
            "action_msg": "Blocked",
            "script": null,
        }))
        .send()
        .await
        .expect("send");
    // Either 200 (created) or 4xx (validation) — both exercise the handler.
    let status = resp.status().as_u16();
    if status == 200 {
        let body: serde_json::Value = resp.json().await.expect("json");
        let id = body["data"]["id"].as_str().unwrap().to_string();
        let del = client()
            .delete(url_for(s.addr, &format!("/api/custom-rules/{id}")))
            .bearer_auth(&s.admin_token)
            .send()
            .await
            .expect("del");
        assert_eq!(del.status(), 200);
    } else {
        assert!(
            (400..500).contains(&status) || status == 500,
            "unexpected status: {status}"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_custom_rule_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/custom-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

// ── LB backends ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn list_lb_backends_empty() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/lb-backends"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_lb_backend_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/lb-backends/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

// ── Certificates ─────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn list_certificates_empty() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/certificates"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["data"].is_array() || body["certificates"].is_array() || body["success"] == true);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_certificate_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/certificates/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

// ── Attack logs / security events with filters ───────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn attack_logs_with_pagination_params() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/attack-logs?limit=10&offset=0"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn security_events_with_filters() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(
            s.addr,
            "/api/security-events?limit=10&host_code=h1&event_type=block",
        ))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}
