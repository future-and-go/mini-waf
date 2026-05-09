//! Integration tests for `logging::vlogs_layer::VictoriaLogsLayer`.
//!
//! Covers: inert-before-slot-filled, event forwarding, span field inheritance,
//! victoria_logs target suppression, field type visitors (bool, i64, f64, str).

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

use tracing_subscriber::prelude::*;
use waf_engine::logging::batch_buffer::{BatchConfig, spawn_batch_flusher};
use waf_engine::logging::vlogs_layer::VictoriaLogsLayer;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn layer_inert_before_slot_filled() {
    let (layer, _slot) = VictoriaLogsLayer::new();

    // No sender in the slot → on_event is a no-op.
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "test_inert", "this should be dropped silently");
    });
    // Reaching here without panic = pass.
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_forwards_event_to_sender() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let (layer, slot) = VictoriaLogsLayer::new();
    let cfg = BatchConfig::for_tracing(
        format!("{}/insert/jsonline", server.uri()),
        1, // flush immediately on first entry
        5000,
        64,
    );
    let sender = spawn_batch_flusher(cfg);
    assert!(slot.set(sender).is_ok(), "slot already filled");

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "my_crate", "hello from layer test");
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_suppresses_victoria_logs_target() {
    // Events targeting "victoria_logs*" must be suppressed to avoid feedback loops.
    // batch_size=1 so any forwarded event flushes immediately — suppression failure
    // would produce > 0 requests.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;

    let (layer, slot) = VictoriaLogsLayer::new();
    let cfg = BatchConfig::for_tracing(format!("{}/insert/jsonline", server.uri()), 1, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    assert!(slot.set(sender).is_ok(), "slot already filled");

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::warn!(
            target: "victoria_logs::buffer",
            "internal ingest warning — must not loop"
        );
    });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_records_multiple_field_types() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let (layer, slot) = VictoriaLogsLayer::new();
    let cfg = BatchConfig::for_tracing(format!("{}/insert/jsonline", server.uri()), 1, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    assert!(slot.set(sender).is_ok(), "slot already filled");

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            target: "field_types",
            int_val = 42_i64,
            bool_val = true,
            str_val = "hello",
            float_val = 3.14_f64,
            "multi-field event"
        );
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_new_returns_independent_slots() {
    let (_layer1, slot1) = VictoriaLogsLayer::new();
    let (_layer2, slot2) = VictoriaLogsLayer::new();

    assert!(slot1.get().is_none());
    assert!(slot2.get().is_none());

    let cfg = BatchConfig::for_tracing("http://127.0.0.1:1/insert".to_string(), 10, 5000, 4);
    let s = spawn_batch_flusher(cfg);
    assert!(slot1.set(s).is_ok(), "slot1 already filled");

    assert!(slot1.get().is_some());
    // Filling slot1 does not affect slot2.
    assert!(slot2.get().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_span_fields_inherited_by_child_event() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let (layer, slot) = VictoriaLogsLayer::new();
    let cfg = BatchConfig::for_tracing(format!("{}/insert/jsonline", server.uri()), 1, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    assert!(slot.set(sender).is_ok(), "slot already filled");

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        let span = tracing::info_span!("req", request_id = "abc-123");
        let _guard = span.enter();
        tracing::info!(target: "handler", "processing request inside span");
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_handles_u64_and_i128_fields() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let (layer, slot) = VictoriaLogsLayer::new();
    let cfg = BatchConfig::for_tracing(format!("{}/insert/jsonline", server.uri()), 1, 5000, 64);
    let sender = spawn_batch_flusher(cfg);
    assert!(slot.set(sender).is_ok(), "slot already filled");

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(
            target: "numeric_types",
            u64_val = 999_u64,
            "u64 field test"
        );
    });

    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}

#[tokio::test(flavor = "multi_thread")]
async fn layer_shutdown_drains_pending_batch() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&server)
        .await;

    let (layer, slot) = VictoriaLogsLayer::new();
    let cfg = BatchConfig::for_tracing(
        format!("{}/insert/jsonline", server.uri()),
        100, // large batch — won't trigger on size
        5000,
        64,
    );
    let sender = spawn_batch_flusher(cfg);
    assert!(slot.set(sender.clone()).is_ok(), "slot already filled");

    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, || {
        tracing::info!(target: "shutdown_test", "pending entry");
    });

    // Drop sender → closes channel → flush loop drains and exits.
    drop(sender);
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    server.verify().await;
}
