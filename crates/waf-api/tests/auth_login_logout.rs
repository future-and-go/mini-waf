// Integration tests for auth endpoints (login / logout / refresh).

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
async fn login_success_returns_tokens() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": s.admin_password }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["success"], true);
    assert!(body["data"]["access_token"].as_str().unwrap().len() > 20);
    assert!(body["data"]["refresh_token"].as_str().unwrap().len() >= 32);
    assert_eq!(body["data"]["token_type"], "Bearer");
    assert_eq!(body["data"]["expires_in"], 86400);
}

#[tokio::test(flavor = "multi_thread")]
async fn login_invalid_password_401() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": "wrong-password" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(body["error"].as_str().unwrap().contains("Invalid credentials"));
}

#[tokio::test(flavor = "multi_thread")]
async fn login_unknown_user_401() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/auth/login"))
        .json(&json!({ "username": "ghost", "password": "x" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn logout_revokes_refresh_token() {
    let s = start_test_server().await;
    // Login first to get refresh token.
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": s.admin_password }))
        .send()
        .await
        .expect("login send")
        .json()
        .await
        .expect("login json");
    let refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();

    // Logout.
    let resp = client()
        .post(url_for(s.addr, "/api/auth/logout"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("logout send");
    assert_eq!(resp.status(), 200);

    // Try to refresh — must fail because token is revoked.
    let r2 = client()
        .post(url_for(s.addr, "/api/auth/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("refresh send");
    assert_eq!(r2.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_returns_new_access_token() {
    let s = start_test_server().await;
    let body: serde_json::Value = client()
        .post(url_for(s.addr, "/api/auth/login"))
        .json(&json!({ "username": "admin", "password": s.admin_password }))
        .send()
        .await
        .expect("login send")
        .json()
        .await
        .expect("login json");
    let refresh = body["data"]["refresh_token"].as_str().unwrap().to_string();

    let resp = client()
        .post(url_for(s.addr, "/api/auth/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .expect("refresh send");
    assert_eq!(resp.status(), 200);
    let r: serde_json::Value = resp.json().await.expect("json");
    assert!(r["data"]["access_token"].as_str().unwrap().len() > 20);
    assert_eq!(r["data"]["token_type"], "Bearer");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_invalid_token_401() {
    let s = start_test_server().await;
    let resp = client()
        .post(url_for(s.addr, "/api/auth/refresh"))
        .json(&json!({ "refresh_token": "no-such-token" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}
