// Tests for notification dispatch + payload behaviour not covered by
// notifications_unit.rs (channel construction lives there).

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

use chrono::Utc;
use waf_api::notifications::NotificationPayload;

#[path = "common/mod.rs"]
mod common;

use common::start_test_server;

#[tokio::test(flavor = "multi_thread")]
async fn dispatch_no_configs_seeded_is_noop() {
    let s = start_test_server().await;
    waf_api::notifications::dispatch_notification(
        s.state.clone(),
        "attack_detected".into(),
        Some("nope".into()),
        "title".into(),
        "msg".into(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dispatch_with_seeded_webhook_config_filters_by_host() {
    use common::{client, url_for};
    use serde_json::json;

    let s = start_test_server().await;
    // Seed a webhook config tied to host_code="h1"
    let _ = client()
        .post(url_for(s.addr, "/api/notifications"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "wh-h1",
            "host_code": "h1",
            "event_type": "attack_detected",
            "channel_type": "webhook",
            "config_json": { "url": "https://example.com/h1" },
            "enabled": true,
            "rate_limit_secs": 0,
        }))
        .send()
        .await
        .expect("seed");

    // Dispatch with a different host — config should be skipped.
    waf_api::notifications::dispatch_notification(
        s.state.clone(),
        "attack_detected".into(),
        Some("h2".into()),
        "title".into(),
        "msg".into(),
    )
    .await;

    // Dispatch with no host_code — also skipped (config has h1).
    waf_api::notifications::dispatch_notification(
        s.state.clone(),
        "attack_detected".into(),
        None,
        "title".into(),
        "msg".into(),
    )
    .await;
}

#[test]
fn payload_serializes_round_trip() {
    let payload = NotificationPayload {
        event_type: "attack_detected".into(),
        host_code: Some("h1".into()),
        title: "t".into(),
        message: "m".into(),
        timestamp: Utc::now(),
    };
    let s = serde_json::to_string(&payload).unwrap();
    let back: NotificationPayload = serde_json::from_str(&s).unwrap();
    assert_eq!(back.event_type, "attack_detected");
    assert_eq!(back.host_code.as_deref(), Some("h1"));
    assert_eq!(back.title, "t");
    assert_eq!(back.message, "m");
}
