//! Integration tests for the relay & proxy intel API.

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

use common::{client, issue_viewer_token, start_test_server_with_tempdir_configs, url_for};

fn valid_relay_body() -> serde_json::Value {
    json!({
        "enabled": true,
        "providers": {
            "asn_classifier": { "enabled": true, "risk_weight": 15 },
            "tor_exit": { "enabled": true, "risk_weight": 30 },
            "datacenter": { "enabled": true, "risk_weight": 15 },
            "proxy_chain": { "enabled": true, "risk_weight": 20 },
            "xff_validator": { "enabled": true, "risk_weight": 10, "max_chain_depth": 3, "reject_private_in_chain": true }
        },
        "intel": {
            "asn_feed": { "url": "https://example.test/asn", "refresh_secs": 86400 },
            "tor_feed": { "url": "https://example.test/tor", "refresh_secs": 3600 },
            "datacenter_set": { "path": "" }
        },
        "trusted_proxies": ["10.0.0.0/8"],
        "risk_weights": { "tor": 35, "datacenter": 15, "bad_asn": 25 }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["providers"]["tor_exit"]["enabled"], true);
    assert_eq!(body["data"]["risk_weights"]["tor"], 30);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_via_get() {
    let (s, tmp) = start_test_server_with_tempdir_configs().await;
    let put = client()
        .put(url_for(s.addr, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_relay_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["risk_weights"]["tor"], 35);
    assert_eq!(body["data"]["trusted_proxies"][0], "10.0.0.0/8");

    let yaml = std::fs::read_to_string(tmp.path().join("configs/relay.yaml")).expect("read yaml");
    assert!(yaml.contains("tor_exit"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let viewer = issue_viewer_token(&s);
    let resp = client()
        .put(url_for(s.addr, "/api/relay/config"))
        .bearer_auth(&viewer)
        .json(&valid_relay_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn intel_status_reflects_configured_urls() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let put = client()
        .put(url_for(s.addr, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_relay_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/relay/intel/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["tor"]["configured_url"], "https://example.test/tor");
    assert_eq!(body["data"]["asn"]["configured_url"], "https://example.test/asn");
}

#[tokio::test(flavor = "multi_thread")]
async fn intel_refresh_validates_yaml_then_succeeds() {
    let (s, tmp) = start_test_server_with_tempdir_configs().await;
    std::fs::write(tmp.path().join("configs/relay.yaml"), "enabled: false\n").expect("seed yaml");

    let resp = client()
        .post(url_for(s.addr, "/api/relay/intel/refresh"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["parsed"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_evaluates_against_real_detector() {
    let (s, tmp) = start_test_server_with_tempdir_configs().await;
    std::fs::write(tmp.path().join("configs/relay.yaml"), "enabled: false\n").expect("seed yaml");

    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/relay/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "client_ip": "203.0.113.5", "xff": "203.0.113.5" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["client_ip"], "203.0.113.5");
    assert!(body["data"]["verdicts"].is_array());
    assert!(body["data"]["real_ip"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_rejects_bad_ip() {
    let (s, tmp) = start_test_server_with_tempdir_configs().await;
    std::fs::write(tmp.path().join("configs/relay.yaml"), "enabled: false\n").expect("seed yaml");

    let resp = client()
        .post(url_for(s.addr, "/api/relay/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "client_ip": "not-an-ip" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}
