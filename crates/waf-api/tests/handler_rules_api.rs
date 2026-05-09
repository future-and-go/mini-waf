// Integration tests for /api/rules/* registry endpoints.

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
async fn rules_registry_list() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/rules/registry"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["rules"].is_array());
    assert!(body["total"].is_number());
}

#[tokio::test(flavor = "multi_thread")]
async fn toggle_rule_persists() {
    let s = start_test_server().await;
    let resp = client()
        .patch(url_for(s.addr, "/api/rules/registry/some-rule-id"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["rule_id"], "some-rule-id");
    assert_eq!(body["data"]["enabled"], false);

    // Toggle back
    let resp2 = client()
        .patch(url_for(s.addr, "/api/rules/registry/some-rule-id"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp2.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_rule_registry_ok() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rules/reload"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_rules_invalid_format_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rules/import"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "source": "/tmp/x.json", "format": "json" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_rules_missing_file_404() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rules/import"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "source": "/tmp/does-not-exist-prx.yaml", "format": "yaml" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_rules_bad_yaml_400() {
    let s = start_test_server().await;
    // Write a bad YAML file
    let path = std::env::temp_dir().join(format!("prx-bad-{}.yaml", uuid::Uuid::new_v4()));
    std::fs::write(&path, "not: [valid yaml").expect("write");
    let resp = client()
        .post(url_for(s.addr, "/api/rules/import"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "source": path.to_string_lossy(), "format": "yaml" }))
        .send()
        .await
        .expect("send");
    let _ = std::fs::remove_file(&path);
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn import_rules_valid_yaml_ok() {
    let s = start_test_server().await;
    let path = std::env::temp_dir().join(format!("prx-good-{}.yaml", uuid::Uuid::new_v4()));
    std::fs::write(
        &path,
        "source: test\nrules:\n  - id: t1\n    name: Test rule\n    category: test\n",
    )
    .expect("write");
    let resp = client()
        .post(url_for(s.addr, "/api/rules/import"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "source": path.to_string_lossy(), "format": "yaml" }))
        .send()
        .await
        .expect("send");
    let _ = std::fs::remove_file(&path);
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["imported"], 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn sqli_scan_reload_default_config() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/sqli-scan/reload"))
        .bearer_auth(&s.admin_token)
        .json(&json!({}))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}
