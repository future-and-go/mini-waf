//! Integration tests for `crowdsec::client::CrowdSecClient` HTTP paths via wiremock.
//!
//! Covers: get_decisions_stream startup/incremental, check_ip hit/miss/404,
//! delete_decision success/error, test_connection success/401/error,
//! push_alerts success/error, machine_auth success/error.

use waf_engine::crowdsec::client::CrowdSecClient;
use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn client(base_url: &str) -> CrowdSecClient {
    CrowdSecClient::new(base_url.to_string(), "test-api-key".to_string()).expect("client")
}

// ── get_decisions_stream ──────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn get_decisions_stream_startup_true_returns_stream() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .and(query_param("startup", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "new": [
                {
                    "id": 1,
                    "origin": "crowdsec",
                    "type": "ban",
                    "scope": "Ip",
                    "value": "1.2.3.4",
                    "duration": "1h",
                    "scenario": "ssh-bf",
                    "created_at": null
                }
            ],
            "deleted": null
        })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let stream = c.get_decisions_stream(true).await.expect("ok");
    let new_decisions = stream.new.expect("new decisions");
    assert_eq!(new_decisions.len(), 1);
    assert_eq!(new_decisions[0].value, "1.2.3.4");
}

#[tokio::test(flavor = "multi_thread")]
async fn get_decisions_stream_startup_false_incremental() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .and(query_param("startup", "false"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "new": null,
            "deleted": null
        })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let stream = c.get_decisions_stream(false).await.expect("ok");
    assert!(stream.new.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_decisions_stream_401_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(401).set_body_string("unauthorized"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.get_decisions_stream(true).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_decisions_stream_bad_json_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.get_decisions_stream(true).await.is_err());
}

// ── check_ip ─────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn check_ip_200_returns_decisions() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "id": 10,
                "origin": "crowdsec",
                "type": "ban",
                "scope": "Ip",
                "value": "9.9.9.9",
                "duration": "2h",
                "scenario": "http-bf",
                "created_at": null
            }
        ])))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let decisions = c.check_ip("9.9.9.9").await.expect("ok");
    assert_eq!(decisions.len(), 1);
    assert_eq!(decisions[0].value, "9.9.9.9");
}

#[tokio::test(flavor = "multi_thread")]
async fn check_ip_null_body_returns_empty_vec() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions"))
        .respond_with(ResponseTemplate::new(200).set_body_string("null"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let decisions = c.check_ip("1.1.1.1").await.expect("ok");
    assert!(decisions.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn check_ip_404_returns_empty_vec() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let decisions = c.check_ip("2.2.2.2").await.expect("ok");
    assert!(decisions.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn check_ip_500_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal error"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.check_ip("3.3.3.3").await.is_err());
}

// ── delete_decision ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn delete_decision_200_returns_ok() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/decisions/42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "deleted": 1 })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    c.delete_decision(42).await.expect("ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_decision_404_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("DELETE"))
        .and(path("/v1/decisions/99"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not found"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.delete_decision(99).await.is_err());
}

// ── test_connection ───────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn test_connection_200_returns_ok_string() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "new": null,
            "deleted": null
        })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let result = c.test_connection().await.expect("ok");
    assert!(result.contains("Connected"), "got: {result}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connection_401_returns_auth_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let err = c.test_connection().await.expect_err("should fail");
    assert!(err.to_string().contains("authentication"), "got: {err}");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_connection_500_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.test_connection().await.is_err());
}

// ── push_alerts ───────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn push_alerts_200_returns_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    c.push_alerts("bearer-token", serde_json::json!([{"key": "val"}]))
        .await
        .expect("ok");
}

#[tokio::test(flavor = "multi_thread")]
async fn push_alerts_422_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/alerts"))
        .respond_with(ResponseTemplate::new(422).set_body_string("invalid"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.push_alerts("tok", serde_json::json!([])).await.is_err());
}

// ── machine_auth ──────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn machine_auth_200_returns_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "jwt-abc123" })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let token = c.machine_auth("machine-id", "password").await.expect("ok");
    assert_eq!(token, "jwt-abc123");
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_auth_403_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.machine_auth("m", "p").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_auth_bad_json_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(c.machine_auth("m", "p").await.is_err());
}
