//! Integration tests for the challenge engine API.

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
        "enabled": false,
        "challenge_type": "pow_challenge",
        "ttl_secs": 120,
        "cookie_name": "__cc",
        "cookie_max_age": 60,
        "same_site": "Lax",
        "http_only": true,
        "branding": { "title": "Verifying…", "message": "Hold on a moment." },
        "nonce_store": { "capacity": 2048, "gc_interval_secs": 30 }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["challenge_type"], "js_challenge");
    assert_eq!(body["data"]["cookie_name"], "__waf_cc");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_via_get() {
    let (s, tmp) = start_test_server_with_tempdir_configs().await;
    let put = client()
        .put(url_for(s.addr, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["challenge_type"], "pow_challenge");
    assert_eq!(body["data"]["cookie_name"], "__cc");
    assert_eq!(body["data"]["branding"]["title"], "Verifying…");

    let yaml = std::fs::read_to_string(tmp.path().join("configs/challenge.yaml")).expect("read yaml");
    assert!(yaml.contains("challenge:"));
    assert!(yaml.contains("pow_challenge"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let viewer = issue_viewer_token(&s);
    let resp = client()
        .put(url_for(s.addr, "/api/challenge/config"))
        .bearer_auth(&viewer)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_malformed_body() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let resp = client()
        .put(url_for(s.addr, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_escapes_html_in_branding() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let html = client()
        .post(url_for(s.addr, "/api/challenge/preview"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "branding": {
                "title": "<script>alert('xss')</script>",
                "message": "& angle <brackets>"
            }
        }))
        .send()
        .await
        .expect("send")
        .text()
        .await
        .expect("text");
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(html.contains("&amp; angle"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_endpoint_returns_zero_counts() {
    let (s, _tmp) = start_test_server_with_tempdir_configs().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/challenge/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["issued"], 0);
    assert_eq!(body["data"]["passed"], 0);
}
