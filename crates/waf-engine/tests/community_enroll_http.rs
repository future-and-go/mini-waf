//! Integration tests for `community::enroll` HTTP paths via wiremock.
//!
//! Covers: enroll_machine success (200 with/without credential), 4xx error,
//! bad JSON response → error.

use waf_engine::community::client::CommunityClient;
use waf_engine::community::enroll::enroll_machine;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── enroll_machine success ────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn enroll_machine_200_returns_credentials() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/machines/enroll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "machine_id": "mach-abc",
            "api_key": "key-xyz",
            "enrollment_credential": "cred-123"
        })))
        .mount(&server)
        .await;

    let client = CommunityClient::new(&server.uri()).expect("client");
    let resp = enroll_machine(&client).await.expect("ok");
    assert_eq!(resp.machine_id, "mach-abc");
    assert_eq!(resp.api_key, "key-xyz");
    assert_eq!(resp.enrollment_credential.as_deref(), Some("cred-123"));
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_machine_200_no_credential_returns_none() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/machines/enroll"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "machine_id": "m2",
            "api_key": "k2",
            "enrollment_credential": null
        })))
        .mount(&server)
        .await;

    let client = CommunityClient::new(&server.uri()).expect("client");
    let resp = enroll_machine(&client).await.expect("ok");
    assert!(resp.enrollment_credential.is_none());
}

// ── enroll_machine error paths ────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn enroll_machine_409_conflict_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/machines/enroll"))
        .respond_with(ResponseTemplate::new(409).set_body_string("machine already enrolled"))
        .mount(&server)
        .await;

    let client = CommunityClient::new(&server.uri()).expect("client");
    let err = enroll_machine(&client).await.expect_err("should fail");
    assert!(err.to_string().contains("409"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_machine_bad_json_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/machines/enroll"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let client = CommunityClient::new(&server.uri()).expect("client");
    assert!(enroll_machine(&client).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn enroll_machine_500_returns_error_with_status() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/api/v1/machines/enroll"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&server)
        .await;

    let client = CommunityClient::new(&server.uri()).expect("client");
    let err = enroll_machine(&client).await.expect_err("should fail");
    assert!(err.to_string().contains("500"), "got: {err}");
}
