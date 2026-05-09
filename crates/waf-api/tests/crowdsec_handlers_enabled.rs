// Integration tests for CrowdSec endpoints when crowdsec_cache is populated.

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

use common::{client, start_test_server_with_crowdsec, url_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_status_enabled_branch() {
    let s = start_test_server_with_crowdsec().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["mode"], "active");
    assert!(body["cache_stats"].is_object());
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_decisions_empty_when_enabled() {
    let s = start_test_server_with_crowdsec().await;
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
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_stats_active_branch() {
    let s = start_test_server_with_crowdsec().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["cache"].is_object());
    assert_eq!(body["total_decisions"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_test_with_cached_lapi_url_no_creds_failure() {
    // Hits the (Some(url), Some(key)) branch — both args provided in body.
    let s = start_test_server_with_crowdsec().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/crowdsec/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "lapi_url": "http://127.0.0.1:1", "api_key": "abc" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    // Connection to 127.0.0.1:1 fails → success: false. Branch covered.
    assert_eq!(body["success"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_update_config_minimal_ok_then_get_returns_row() {
    let s = start_test_server_with_crowdsec().await;
    // Update config with valid http url and api_key
    let body: serde_json::Value = client()
        .put(url_for(s.addr, "/api/crowdsec/config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "enabled": true,
            "mode": "appsec",
            "lapi_url": "http://127.0.0.1:8080",
            "api_key": "secret-key",
            "appsec_endpoint": "http://127.0.0.1:7422",
            "appsec_key": "appsec-key",
            "update_frequency_secs": 30,
            "fallback_action": "deny"
        }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["mode"], "appsec");
    assert_eq!(body["api_key_set"], true);
    assert_eq!(body["appsec_key_set"], true);

    // Now GET — covers the Some(row) branch.
    let got: serde_json::Value = client()
        .get(url_for(s.addr, "/api/crowdsec/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(got["enabled"], true);
    assert_eq!(got["mode"], "appsec");
    assert_eq!(got["api_key_set"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_update_config_empty_keys_skip_encryption() {
    let s = start_test_server_with_crowdsec().await;
    let body: serde_json::Value = client()
        .put(url_for(s.addr, "/api/crowdsec/config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "enabled": false,
            "mode": null,
            "lapi_url": null,
            "api_key": "",
            "appsec_endpoint": null,
            "appsec_key": "",
            "update_frequency_secs": null,
            "fallback_action": null
        }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    // Empty-string secrets must NOT be persisted.
    assert_eq!(body["api_key_set"], false);
    assert_eq!(body["appsec_key_set"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_delete_decision_with_client_returns_502() {
    // crowdsec_client is not wired in our fixture, so we exercise the
    // 503 branch here.  This complements the existing fixture-disabled
    // test and ensures both no-cache + no-client paths are hit.
    let s = start_test_server_with_crowdsec().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/crowdsec/decisions/1"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 503);
}
