// Integration tests for CrowdSec endpoints — degraded responses when
// crowdsec_cache/crowdsec_client are None.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_status_disabled() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["enabled"], false);
    assert!(body["connection_msg"].as_str().unwrap().contains("not enabled"));
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_decisions_empty_when_disabled() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/decisions"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 0);
    assert!(body["decisions"].as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_delete_decision_503_when_disabled() {
    let s = start_test_server().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/crowdsec/decisions/42"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 503);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_test_no_credentials_failure() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/crowdsec/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({}))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_test_invalid_scheme() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/crowdsec/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "lapi_url": "file:///etc/passwd", "api_key": "x" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_get_config_default() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["enabled"], false);
    assert_eq!(body["mode"], "bouncer");
    assert_eq!(body["fallback_action"], "allow");
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_update_config_invalid_url_400() {
    let s = start_test_server().await;
    let resp = client()
        .put(url_for(s.addr, "/api/crowdsec/config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "enabled": true,
            "mode": "bouncer",
            "lapi_url": "ftp://bad.example.com",
            "api_key": null,
            "appsec_endpoint": null,
            "appsec_key": null,
            "update_frequency_secs": 10,
            "fallback_action": "allow",
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_stats_disabled_says_inactive() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["enabled"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_events_returns_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/events"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 0);
    assert!(body["events"].as_array().unwrap().is_empty());
}
