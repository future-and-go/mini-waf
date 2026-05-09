// Integration tests for JWT auth middleware on protected routes.

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

#[tokio::test(flavor = "multi_thread")]
async fn protected_route_no_token_401() {
    let s = start_test_server().await;
    let resp = client().get(url_for(s.addr, "/api/hosts")).send().await.expect("send");
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], false);
    assert_eq!(body["error"], "Authorization header required");
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_route_invalid_token_401() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/hosts"))
        .header("authorization", "Bearer not-a-real-jwt")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["error"], "Invalid or expired token");
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_route_malformed_header_401() {
    let s = start_test_server().await;
    // Missing "Bearer " prefix.
    let resp = client()
        .get(url_for(s.addr, "/api/hosts"))
        .header("authorization", s.admin_token.clone())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn protected_route_with_valid_token_passes_auth() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/hosts"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    // Auth succeeded → handler returned 200 with empty list.
    assert_eq!(resp.status(), 200);
}

#[tokio::test(flavor = "multi_thread")]
async fn public_login_route_does_not_require_token() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/auth/login"))
        .json(&serde_json::json!({ "username": "admin", "password": s.admin_password }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}
