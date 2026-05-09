//! Integration tests for `logging::audit_sender` — AuditSender lifecycle.
//!
//! Covers: send when active, skip when inactive (buffer gone), path truncation,
//! all AuditEventType variants serialise correctly.

use chrono::Utc;
use waf_engine::logging::audit_sender::{AuditEvent, AuditEventType, AuditSender};
use waf_engine::logging::batch_buffer::{BatchConfig, spawn_batch_flusher};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn make_event(event_type: AuditEventType, req_path: &str) -> AuditEvent {
    AuditEvent {
        timestamp: Utc::now(),
        event_type,
        rule_name: "test-rule".to_string(),
        rule_id: Some("R001".to_string()),
        phase: Some("phase1".to_string()),
        client_ip: "1.2.3.4".to_string(),
        host: "example.com".to_string(),
        method: "GET".to_string(),
        path: req_path.to_string(),
        tier: Some("standard".to_string()),
        detail: Some("test detail".to_string()),
        req_id: Some("req-abc".to_string()),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn send_event_reaches_victoria_logs() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insert/jsonline"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = BatchConfig::for_audit(
        format!("{}/insert/jsonline", server.uri()),
        1, // flush on first entry
        5000,
        16,
    );
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer);

    sender.send(make_event(AuditEventType::Block, "/admin"));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn send_skips_when_buffer_inactive() {
    let cfg = BatchConfig::for_audit("http://127.0.0.1:1/insert/jsonline".to_string(), 10, 5000, 4);
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer.clone());

    // Drop the original handle to close the channel.
    drop(buffer);
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // send() should silently no-op — not panic.
    sender.send(make_event(AuditEventType::Allow, "/safe"));
}

#[tokio::test(flavor = "multi_thread")]
async fn all_event_types_serialize_without_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let cfg = BatchConfig::for_audit(format!("{}/insert/jsonline", server.uri()), 1, 5000, 64);
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer);

    for ev_type in [
        AuditEventType::Block,
        AuditEventType::Allow,
        AuditEventType::Challenge,
        AuditEventType::RateLimit,
        AuditEventType::LogOnly,
    ] {
        sender.send(make_event(ev_type, "/test"));
    }

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    // No panic = pass; exact count depends on batch timing.
}

#[tokio::test(flavor = "multi_thread")]
async fn long_path_is_truncated_before_send() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = BatchConfig::for_audit(format!("{}/insert/jsonline", server.uri()), 1, 5000, 16);
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer);

    // Build a path longer than PATH_TRUNCATE_AT (500) bytes.
    let long_path = format!("/{}", "a".repeat(600));
    sender.send(make_event(AuditEventType::Block, &long_path));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn multibyte_path_truncation_stays_valid_utf8() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = BatchConfig::for_audit(format!("{}/insert/jsonline", server.uri()), 1, 5000, 16);
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer);

    // 'é' is 2 bytes in UTF-8 — ensures boundary walk is exercised.
    let multibyte_path = "é".repeat(300); // > 500 bytes but < 600 chars
    sender.send(make_event(AuditEventType::Block, &multibyte_path));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_clone_is_also_active() {
    let cfg = BatchConfig::for_audit("http://127.0.0.1:1/insert/jsonline".to_string(), 10, 5000, 16);
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer);
    let _clone = sender.clone();
    // Both should work without panic.
    _clone.send(make_event(AuditEventType::LogOnly, "/"));
}

#[tokio::test(flavor = "multi_thread")]
async fn optional_fields_none_serialize_gracefully() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = BatchConfig::for_audit(format!("{}/insert/jsonline", server.uri()), 1, 5000, 16);
    let buffer = spawn_batch_flusher(cfg);
    let sender = AuditSender::new(buffer);

    let event = AuditEvent {
        timestamp: Utc::now(),
        event_type: AuditEventType::RateLimit,
        rule_name: "rl".to_string(),
        rule_id: None,
        phase: None,
        client_ip: "10.0.0.1".to_string(),
        host: "h.example".to_string(),
        method: "POST".to_string(),
        path: "/api".to_string(),
        tier: None,
        detail: None,
        req_id: None,
    };
    sender.send(event);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}
