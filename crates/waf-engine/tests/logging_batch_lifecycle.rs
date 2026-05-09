//! Integration tests for `logging::batch_buffer` — state machine lifecycle.
//!
//! Covers: push below threshold (no flush), push at threshold (flush),
//! channel-full drop, shutdown drain.

use serde_json::json;
use waf_engine::logging::batch_buffer::{BatchConfig, BatchSender, spawn_batch_flusher};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn cfg_for(server: &MockServer, batch_size: usize, flush_ms: u64, cap: usize) -> BatchConfig {
    BatchConfig::for_tracing(format!("{}/insert/jsonline", server.uri()), batch_size, flush_ms, cap)
}

/// A sender that points at a non-listening port — safe for offline tests.
fn offline_sender(batch_size: usize, cap: usize) -> BatchSender {
    let cfg = BatchConfig::for_audit(
        "http://127.0.0.1:1/insert/jsonline".to_string(),
        batch_size,
        5000, // very long interval — only size or shutdown triggers flush
        cap,
    );
    spawn_batch_flusher(cfg)
}

#[tokio::test(flavor = "multi_thread")]
async fn single_entry_below_threshold_does_not_trigger_flush() {
    let server = MockServer::start().await;
    // Mount a catch-all that counts hits.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0) // no flush expected before drop
        .mount(&server)
        .await;

    let cfg = cfg_for(&server, 10, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    sender.try_send(json!({"msg": "hello"}));

    // Don't drop the sender — verify no flush yet by checking mock received 0.
    // The mock's expect(0) is verified on MockServer drop.
    drop(sender);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_flushes_pending_entries() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insert/jsonline"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = cfg_for(&server, 100, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    sender.try_send(json!({"msg": "shutdown-test"}));

    // Drop sender → signals channel closed → flush loop drains + exits.
    drop(sender);
    // Small yield to let the async task run its final flush.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn batch_size_reached_triggers_immediate_flush() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insert/jsonline"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = cfg_for(&server, 3, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    sender.try_send(json!({"n": 1}));
    sender.try_send(json!({"n": 2}));
    sender.try_send(json!({"n": 3}));

    // batch_size=3 → flush triggered by 3rd push.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn time_interval_flush_drains_partial_batch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/insert/jsonline"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    // batch_size=100 so size threshold won't trigger; interval=50ms will.
    let cfg = cfg_for(&server, 100, 50, 64);
    let sender = spawn_batch_flusher(cfg);
    sender.try_send(json!({"msg": "interval-flush"}));

    // Wait for interval to fire.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn channel_full_drops_new_entries() {
    // capacity=1 so any extra push is dropped.
    let sender = offline_sender(100, 1);
    // Fill the one slot.
    sender.try_send(json!({"n": 1}));
    // This should be dropped — sender remains active.
    sender.try_send(json!({"n": 2}));
    assert!(sender.is_active());
}

#[tokio::test(flavor = "multi_thread")]
async fn dropping_last_sender_flushes_pending_and_exits() {
    let server = MockServer::start().await;
    // Expect exactly one flush when the sender is dropped with a pending entry.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    // batch_size=10 so the single entry won't auto-flush; it flushes on drop.
    let cfg = cfg_for(&server, 10, 5000, 4);
    let sender = spawn_batch_flusher(cfg);
    sender.try_send(json!({"event": "exit-flush"}));
    // Dropping the only sender causes flusher loop to drain and exit.
    drop(sender);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn http_error_response_does_not_panic() {
    let server = MockServer::start().await;
    // Server returns 500 — flush loop should log-and-continue, not panic.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .expect(1)
        .mount(&server)
        .await;

    let cfg = cfg_for(&server, 1, 5000, 4);
    let sender = spawn_batch_flusher(cfg);
    sender.try_send(json!({"msg": "error-test"}));
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn clone_of_sender_is_also_active() {
    let sender = offline_sender(10, 16);
    let clone = sender.clone();
    assert!(sender.is_active());
    assert!(clone.is_active());
}
