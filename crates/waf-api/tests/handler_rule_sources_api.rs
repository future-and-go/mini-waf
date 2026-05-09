// Integration tests for /api/rule-sources/* (FR-007 DB-backed CRUD).

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::{client, start_test_server, url_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn list_rule_sources_empty() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert!(body["sources"].is_array());
    assert_eq!(body["sources"].as_array().unwrap().len(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rule_source_invalid_name_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "", "source_type": "remote_url", "url": "http://x.test/r.yaml" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rule_source_bad_chars_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "bad name!", "source_type": "remote_url", "url": "http://x.test/r.yaml" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rule_source_invalid_type_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "src1", "source_type": "ftp", "url": "ftp://x" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rule_source_invalid_format_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "src1",
            "source_type": "remote_url",
            "url": "http://x.test/r.xml",
            "format": "xml",
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rule_source_remote_url_missing_url_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "src1", "source_type": "remote_url" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rule_source_local_file_missing_path_400() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "name": "src1", "source_type": "local_file" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_list_then_delete_rule_source() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "name": "owasp-test",
            "source_type": "remote_url",
            "url": "https://example.com/owasp.yaml",
            "format": "yaml",
        }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 201);

    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/rule-sources"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let arr = body["sources"].as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["name"], "owasp-test");
    assert_eq!(arr[0]["type"], "remote_url");

    let del = client()
        .delete(url_for(s.addr, "/api/rule-sources/owasp-test"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(del.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_duplicate_rule_source_409() {
    let s = start_test_server().await;
    for _ in 0..2 {
        let resp = client()
            .post(url_for(s.addr, "/api/rule-sources"))
            .bearer_auth(&s.admin_token)
            .json(&json!({
                "name": "dup-src",
                "source_type": "local_file",
                "path": "/tmp/x.yaml",
                "format": "yaml",
            }))
            .send()
            .await
            .expect("send");
        // First → 201, second → 409.
        if resp.status() == 201 {
            continue;
        }
        assert_eq!(resp.status(), 409);
        return;
    }
    panic!("expected second create to return 409");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_unknown_rule_source_404() {
    let s = start_test_server().await;
    let resp = client()
        .delete(url_for(s.addr, "/api/rule-sources/does-not-exist"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("del");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_all_rule_sources_ok_when_empty() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources/sync"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["ok"], true);
    assert_eq!(body["touched"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn sync_unknown_rule_source_404() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/rule-sources/missing/sync"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}
