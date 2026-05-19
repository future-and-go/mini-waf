//! Integration tests for `crowdsec::pusher::CrowdSecPusher` and
//! `crowdsec::sync::run_decision_sync` HTTP paths via wiremock.
//!
//! Covers: push_detection flush_batch (auth success + push success/fail,
//! auth failure → silent), run_flush_task shutdown drain,
//! run_decision_sync startup pull + incremental + shutdown.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::sync::Arc;

use tokio::sync::watch;
use waf_common::{DetectionResult, Phase};
use waf_engine::crowdsec::cache::DecisionCache;
use waf_engine::crowdsec::client::CrowdSecClient;
use waf_engine::crowdsec::config::{CrowdSecConfig, PusherConfig};
use waf_engine::crowdsec::pusher::CrowdSecPusher;
use waf_engine::crowdsec::sync::run_decision_sync;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ───────────────────────────────────────────────────────────────────

fn lapi_client(base_url: &str) -> Arc<CrowdSecClient> {
    Arc::new(CrowdSecClient::new(base_url.to_string(), "api-key".to_string()).expect("client"))
}

fn detection() -> DetectionResult {
    DetectionResult {
        rule_id: Some("R1".to_string()),
        rule_name: "SqlInjection".to_string(),
        phase: Phase::SqlInjection,
        detail: "DROP TABLE".to_string(),
        rule_action: None,
        action_status: None,
    }
}

fn pusher(client: Arc<CrowdSecClient>) -> Arc<CrowdSecPusher> {
    Arc::new(CrowdSecPusher::new(
        client,
        PusherConfig {
            login: "machine-id".to_string(),
            password: "password".to_string(),
        },
    ))
}

// ── flush_batch auth + push success ──────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn flush_batch_auth_success_then_push_alerts() {
    let server = MockServer::start().await;

    // machine_auth endpoint
    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "jwt-tok" })))
        .mount(&server)
        .await;

    // push_alerts endpoint
    Mock::given(method("POST"))
        .and(path("/v1/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let p = pusher(lapi_client(&server.uri()));
    let det = detection();

    // push_detection accumulates in buffer; at BATCH_SIZE=50 it flushes.
    // Manually trigger a flush by filling the buffer via run_flush_task shutdown.
    p.push_detection("1.2.3.4", &det).await;

    let (tx, rx) = watch::channel(false);
    let p2 = Arc::clone(&p);
    let handle = tokio::spawn(async move { p2.run_flush_task(rx).await });

    // Give the task a moment to start, then signal shutdown → drain flush.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn flush_batch_auth_failure_does_not_panic() {
    let server = MockServer::start().await;

    // machine_auth fails
    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
        .mount(&server)
        .await;

    let p = pusher(lapi_client(&server.uri()));
    p.push_detection("2.3.4.5", &detection()).await;

    let (tx, rx) = watch::channel(false);
    let p2 = Arc::clone(&p);
    let handle = tokio::spawn(async move { p2.run_flush_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = handle.await;
    // Should not panic regardless of auth failure
}

#[tokio::test(flavor = "multi_thread")]
async fn flush_batch_push_failure_does_not_panic() {
    let server = MockServer::start().await;

    // auth succeeds, push_alerts fails
    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "tok" })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/alerts"))
        .respond_with(ResponseTemplate::new(500).set_body_string("err"))
        .mount(&server)
        .await;

    let p = pusher(lapi_client(&server.uri()));
    p.push_detection("3.4.5.6", &detection()).await;

    let (tx, rx) = watch::channel(false);
    let p2 = Arc::clone(&p);
    let handle = tokio::spawn(async move { p2.run_flush_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = handle.await;
}

// ── push_detection fills buffer to BATCH_SIZE → auto-flush ───────────────────

#[tokio::test(flavor = "multi_thread")]
async fn push_detection_auto_flush_at_batch_size_50() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/v1/watchers/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "token": "tok" })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/alerts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(1)
        .mount(&server)
        .await;

    let p = pusher(lapi_client(&server.uri()));
    let det = detection();

    // Push exactly 50 events to trigger auto-flush (BATCH_SIZE = 50)
    for _ in 0..50 {
        p.push_detection("4.5.6.7", &det).await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    server.verify().await;
}

// ── run_flush_task empty buffer on shutdown → no POST ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn run_flush_task_empty_buffer_shutdown_sends_no_post() {
    let server = MockServer::start().await;
    // No mocks registered — any unexpected request would be an error.

    let p = pusher(lapi_client(&server.uri()));
    let (tx, rx) = watch::channel(false);
    let p2 = Arc::clone(&p);
    let handle = tokio::spawn(async move { p2.run_flush_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    // No POST should have been made (empty buffer)
    assert_eq!(server.received_requests().await.unwrap().len(), 0);
}

// ── run_decision_sync startup pull ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn run_decision_sync_startup_pull_populates_cache() {
    let server = MockServer::start().await;

    // Startup pull (startup=true) returns 1 decision
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "new": [
                { "id": 1, "origin": "crowdsec", "type": "ban", "scope": "Ip",
                  "value": "5.5.5.5", "duration": "1h", "scenario": "ssh-bf", "created_at": null }
            ],
            "deleted": null
        })))
        .mount(&server)
        .await;

    let client = lapi_client(&server.uri());
    let cache = Arc::new(DecisionCache::new(3600));
    let config = CrowdSecConfig {
        lapi_url: server.uri(),
        update_frequency_secs: 3600,
        ..CrowdSecConfig::default()
    };

    let (tx, rx) = watch::channel(false);
    let cache2 = Arc::clone(&cache);
    let handle = tokio::spawn(run_decision_sync(client, cache2, config, rx));

    // Give the startup pull time to complete, then shut down
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

    // Cache should have the decision
    let ip: std::net::IpAddr = "5.5.5.5".parse().expect("ip");
    assert!(cache.check_ip(&ip).is_some(), "cache should contain 5.5.5.5");
}

#[tokio::test(flavor = "multi_thread")]
async fn run_decision_sync_startup_pull_failure_is_non_fatal() {
    let server = MockServer::start().await;

    // Startup pull fails — LAPI returns 500
    Mock::given(method("GET"))
        .and(path("/v1/decisions/stream"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let client = lapi_client(&server.uri());
    let cache = Arc::new(DecisionCache::new(60));
    let config = CrowdSecConfig {
        lapi_url: server.uri(),
        update_frequency_secs: 3600,
        ..CrowdSecConfig::default()
    };

    let (tx, rx) = watch::channel(false);
    let cache2 = Arc::clone(&cache);
    let handle = tokio::spawn(run_decision_sync(client, cache2, config, rx));

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;

    // No panic — cache is empty
    assert_eq!(cache.stats().total_cached, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn run_decision_sync_shutdown_exits_promptly() {
    // Use unreachable server — startup pull fails immediately, task should then
    // wait for interval or shutdown. Send shutdown right away.
    let client = lapi_client("http://127.0.0.1:1");
    let cache = Arc::new(DecisionCache::new(60));
    let config = CrowdSecConfig {
        lapi_url: "http://127.0.0.1:1".to_string(),
        update_frequency_secs: 3600,
        ..CrowdSecConfig::default()
    };

    let (tx, rx) = watch::channel(false);
    let cache2 = Arc::clone(&cache);
    let handle = tokio::spawn(run_decision_sync(client, cache2, config, rx));

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let _ = tx.send(true);

    tokio::time::timeout(std::time::Duration::from_secs(3), handle)
        .await
        .expect("sync task exited within timeout")
        .expect("no panic");
}
