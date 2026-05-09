// Integration tests for /api/notifications.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn list_notifications_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/notifications"))
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
async fn create_notification_invalid_channel_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "n1",
            "host_code": null,
            "event_type": "attack_detected",
            "channel_type": "carrier-pigeon",
            "config_json": {},
            "enabled": true,
            "rate_limit_secs": 300,
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_notification_webhook_then_delete() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "wh",
            "host_code": null,
            "event_type": "attack_detected",
            "channel_type": "webhook",
            "config_json": { "url": "https://example.com/hook" },
            "enabled": true,
            "rate_limit_secs": 300,
        }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = body["data"]["id"].as_str().unwrap().to_string();

    let resp = client()
        .delete(url_for(s.addr, &format!("/api/notifications/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_notification_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .delete(url_for(s.addr, &format!("/api/notifications/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_log_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/notifications/log"))
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
async fn test_unknown_notification_404() {
    let s = start_test_server().await;
    let id = uuid::Uuid::new_v4();
    let resp = client()
        .post(url_for(s.addr, &format!("/api/notifications/{id}/test")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_notification_telegram_then_test_returns_500() {
    // We seed a telegram config and trigger /test. The Telegram API will
    // either fail (network) or reject (invalid token) — either way the
    // handler exercises build_channel(telegram) + chan.send().
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "tg",
            "host_code": null,
            "event_type": "attack_detected",
            "channel_type": "telegram",
            "config_json": { "bot_token": "123:fake", "chat_id": "1" },
            "enabled": true,
            "rate_limit_secs": 0,
        }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = body["data"]["id"].as_str().unwrap().to_string();

    let resp = client()
        .post(url_for(s.addr, &format!("/api/notifications/{id}/test")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    // Telegram API will reject the fake token → handler returns 500 (Internal).
    assert_eq!(resp.status(), 500);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_notification_email_then_test_returns_500() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "em",
            "host_code": null,
            "event_type": "attack_detected",
            "channel_type": "email",
            "config_json": {
                "smtp_host": "127.0.0.1",
                "smtp_port": 1,
                "username": "u",
                "password": "p",
                "from": "noreply@example.com",
                "to": ["dest@example.com"],
            },
            "enabled": true,
            "rate_limit_secs": 0,
        }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let id = body["data"]["id"].as_str().unwrap().to_string();

    let resp = client()
        .post(url_for(s.addr, &format!("/api/notifications/{id}/test")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    // SMTP connect to port 1 will fail → 500.
    assert_eq!(resp.status(), 500);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_notifications_with_host_filter() {
    let s = start_test_server().await;
    // Seed two configs: one with host_code, one without.
    let _ = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "wh-host",
            "host_code": "h1",
            "event_type": "attack_detected",
            "channel_type": "webhook",
            "config_json": { "url": "https://example.com/h1" },
            "enabled": true,
            "rate_limit_secs": 60,
        }))
        .send()
        .await
        .expect("send");
    let _ = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "wh-global",
            "host_code": null,
            "event_type": "attack_detected",
            "channel_type": "webhook",
            "config_json": { "url": "https://example.com/global" },
            "enabled": true,
            "rate_limit_secs": 60,
        }))
        .send()
        .await
        .expect("send");

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/notifications?host_code=h1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], true);
    let arr = body["data"].as_array().unwrap();
    assert!(!arr.is_empty());
}
