//! Integration tests for the device fingerprinting API.

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

fn valid_body() -> serde_json::Value {
    json!({
        "enabled": true,
        "capture": {
            "tls": { "enabled": true, "algorithms": ["ja3"] },
            "h2":  { "enabled": false, "hash": "akamai" }
        },
        "store": { "backend": "memory", "ttl_secs": 7200 },
        "providers": {
            "ip_hopping":   { "enabled": true,  "window_secs": 600, "max_distinct_ips": 3,  "signal_weight": 25 },
            "ua_blocklist": { "enabled": false, "blocklist_patterns": ["sqlmap"], "signal_weight": 30 }
        },
        "behavior": {
            "window_size": 16,
            "actor_ttl_secs": 600,
            "burst_interval":   { "enabled": true, "threshold_ms": 50, "min_consecutive": 5, "risk_delta": 15 },
            "regularity":       { "enabled": true, "min_samples": 6, "cv_threshold": 0.15, "min_mean_ms": 100, "risk_delta": 10 },
            "zero_depth":       { "enabled": true, "min_samples": 4, "critical_hits_required": 2, "risk_delta": 10 },
            "missing_referer":  {
                "enabled": true, "risk_delta": 5,
                "exempt_paths":    ["/"],
                "exempt_prefixes": ["/static/"]
            }
        }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/device-fp/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], false);
    assert!(body["data"]["providers"]["ip_hopping"].is_object());
    assert!(body["data"]["providers"]["ua_entropy"].is_object());
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_via_get() {
    let (s, tmp) = start_test_server_with_tempdir_configs().await;
    let put = client()
        .put(url_for(s.addr, "/api/device-fp/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/device-fp/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["providers"]["ip_hopping"]["enabled"], true);
    assert_eq!(body["data"]["providers"]["ua_blocklist"]["enabled"], false);

    let yaml = std::fs::read_to_string(tmp.path().join("configs/device-fp.yaml")).expect("read yaml");
    assert!(yaml.contains("device_fp:"));
    assert!(yaml.contains("ip_hopping"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let viewer = issue_viewer_token(&s);
    let resp = client()
        .put(url_for(s.addr, "/api/device-fp/config"))
        .bearer_auth(&viewer)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_non_object_body() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let resp = client()
        .put(url_for(s.addr, "/api/device-fp/config"))
        .bearer_auth(&s.admin_token)
        .json(&json!([1, 2, 3]))
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn recent_endpoint_returns_empty_list() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/device-fp/recent"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"], json!([]));
    assert_eq!(body["total"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn conflicts_endpoint_returns_empty_list() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/device-fp/conflicts"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"], json!([]));
    assert_eq!(body["total"], 0);
}
