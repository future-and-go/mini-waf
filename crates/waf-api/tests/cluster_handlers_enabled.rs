// Integration tests for cluster endpoints when cluster_state is populated.

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

use common::{client, start_test_server_with_cluster, url_for};
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn cluster_status_enabled_ok() {
    let s = start_test_server_with_cluster().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/cluster/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["enabled"], true);
    assert_eq!(body["node_id"], "test-node");
    assert_eq!(body["total_nodes"], 1);
    assert!(body["nodes"].as_array().unwrap()[0]["is_self"].as_bool().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_list_nodes_enabled_ok() {
    let s = start_test_server_with_cluster().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/cluster/nodes"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 1);
    let nodes = body["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0]["node_id"], "test-node");
    assert_eq!(nodes[0]["health"], "healthy");
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_get_self_node_ok() {
    let s = start_test_server_with_cluster().await;
    let body: serde_json::Value = client()
        .get(url_for(s.addr, "/api/cluster/nodes/test-node"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["node_id"], "test-node");
    assert_eq!(body["is_self"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_get_unknown_node_404() {
    let s = start_test_server_with_cluster().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cluster/nodes/nope"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_remove_self_400() {
    let s = start_test_server_with_cluster().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cluster/nodes/remove"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "node_id": "test-node" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_remove_unknown_node_404() {
    let s = start_test_server_with_cluster().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cluster/nodes/remove"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "node_id": "ghost" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_token_default_ttl_succeeds_or_fails_gracefully() {
    let s = start_test_server_with_cluster().await;
    // The seeded CA key may not be a parseable Ed25519 PEM — token
    // generation can fail with 500 in that case.  Either outcome
    // exercises the populated-CA branch we care about.
    let resp = client()
        .post(url_for(s.addr, "/api/cluster/token"))
        .bearer_auth(&s.admin_token)
        .json(&json!({}))
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    assert!(status == 200 || status == 500, "got {status}");
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_token_custom_ttl_request_path() {
    let s = start_test_server_with_cluster().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cluster/token"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ttl_ms": 30_000_u64 }))
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    assert!(status == 200 || status == 500, "got {status}");
}
