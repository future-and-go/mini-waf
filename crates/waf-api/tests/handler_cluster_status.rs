// Integration tests for cluster endpoints — cluster_state is None in fixture,
// so all cluster routes return 404 ("cluster not enabled").

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
async fn cluster_status_disabled_404() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cluster/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_nodes_disabled_404() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cluster/nodes"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_node_detail_disabled_404() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/cluster/nodes/some-id"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_token_disabled_404() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cluster/token"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ttl_ms": 60000 }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn cluster_remove_node_disabled_404() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/cluster/nodes/remove"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "node_id": "x" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 404);
}
