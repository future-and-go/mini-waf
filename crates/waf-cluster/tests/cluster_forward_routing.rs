//! Tests for `PendingForwards`, `forward_write`, and `is_write_method`.
//!
//! These exercise the worker → main API forwarding registry without needing a
//! real Postgres database — the registry layer is purely an in-memory oneshot
//! correlation table.
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
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    unused_imports
)]

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::mpsc;

use waf_cluster::cluster_forward::{PendingForwards, forward_write, is_write_method};
use waf_cluster::protocol::{ApiForwardResponse, ClusterMessage};

#[test]
fn write_method_classification() {
    for m in ["POST", "PUT", "DELETE", "PATCH", "post", "Put"] {
        assert!(is_write_method(m), "{m} should be a write method");
    }
    for m in ["GET", "HEAD", "OPTIONS", "TRACE", "get"] {
        assert!(!is_write_method(m), "{m} should not be a write method");
    }
}

#[tokio::test]
async fn pending_forwards_register_and_resolve() {
    let p = PendingForwards::new();
    let rx = p.register("req-1".to_string()).await;
    assert_eq!(p.pending_count().await, 1);

    p.resolve(ApiForwardResponse {
        request_id: "req-1".to_string(),
        status: 201,
        body: vec![1, 2, 3],
    })
    .await;

    let resp = rx.await.expect("oneshot resolved");
    assert_eq!(resp.status, 201);
    assert_eq!(resp.body, vec![1, 2, 3]);
    assert_eq!(p.pending_count().await, 0);
}

#[tokio::test]
async fn pending_forwards_resolve_unknown_is_noop() {
    let p = PendingForwards::new();
    p.resolve(ApiForwardResponse {
        request_id: "ghost".to_string(),
        status: 200,
        body: vec![],
    })
    .await;
    assert_eq!(p.pending_count().await, 0);
}

#[tokio::test]
async fn pending_forwards_resolve_dropped_receiver_logs_only() {
    let p = PendingForwards::new();
    let rx = p.register("orphan".to_string()).await;
    drop(rx);
    // Receiver dropped before sender — resolve should not panic, just debug-log.
    p.resolve(ApiForwardResponse {
        request_id: "orphan".to_string(),
        status: 500,
        body: vec![],
    })
    .await;
    assert_eq!(p.pending_count().await, 0);
}

#[tokio::test]
async fn pending_forwards_cancel_all_drops_receivers() {
    let p = PendingForwards::new();
    let rx1 = p.register("a".to_string()).await;
    let rx2 = p.register("b".to_string()).await;
    assert_eq!(p.pending_count().await, 2);

    p.cancel_all().await;
    assert_eq!(p.pending_count().await, 0);

    assert!(rx1.await.is_err());
    assert!(rx2.await.is_err());
}

#[tokio::test]
async fn forward_write_round_trip() {
    let pending = PendingForwards::new();
    let (tx, mut rx) = mpsc::channel::<ClusterMessage>(8);
    let pending_clone = pending.clone();

    let handle = tokio::spawn(async move {
        forward_write(
            &tx,
            &pending_clone,
            "req-42".to_string(),
            "POST".to_string(),
            "/v1/rules".to_string(),
            b"body".to_vec(),
            HashMap::new(),
            5_000,
        )
        .await
    });

    let outgoing = rx.recv().await.expect("forward message queued");
    match outgoing {
        ClusterMessage::ApiForward(fw) => {
            assert_eq!(fw.request_id, "req-42");
            assert_eq!(fw.method, "POST");
            assert_eq!(fw.path, "/v1/rules");
            assert_eq!(fw.body, b"body");
        }
        other => panic!("expected ApiForward, got {other:?}"),
    }

    pending
        .resolve(ApiForwardResponse {
            request_id: "req-42".to_string(),
            status: 200,
            body: b"ok".to_vec(),
        })
        .await;

    let resp = handle.await.expect("join").expect("forward ok");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body, b"ok");
}

#[tokio::test(start_paused = true)]
async fn forward_write_times_out_when_no_response() {
    let pending = PendingForwards::new();
    let pending_clone = pending.clone();
    let (tx, _rx) = mpsc::channel::<ClusterMessage>(8);

    let h = tokio::spawn(async move {
        forward_write(
            &tx,
            &pending_clone,
            "req-timeout".to_string(),
            "PUT".to_string(),
            "/x".to_string(),
            Vec::new(),
            HashMap::new(),
            10,
        )
        .await
    });

    tokio::time::advance(Duration::from_millis(100)).await;
    let res = h.await.expect("join");
    assert!(res.is_err(), "must time out");
    // Regression: pre-fix the timeout path leaked the oneshot::Sender forever.
    assert_eq!(
        pending.pending_count().await,
        0,
        "timeout must drop the pending entry to avoid unbounded HashMap growth"
    );
}

#[tokio::test]
async fn forward_write_errors_when_outbound_closed() {
    let pending = PendingForwards::new();
    let (tx, rx) = mpsc::channel::<ClusterMessage>(1);
    drop(rx);

    let res = forward_write(
        &tx,
        &pending,
        "req-closed".to_string(),
        "DELETE".to_string(),
        "/y".to_string(),
        Vec::new(),
        HashMap::new(),
        1_000,
    )
    .await;

    let err = res.expect_err("must fail when channel closed");
    let msg = format!("{err}");
    assert!(msg.contains("outbound channel closed"), "msg = {msg}");
    // Regression: pre-fix a send-failure also leaked the registered entry.
    assert_eq!(
        pending.pending_count().await,
        0,
        "send failure must drop the pending entry"
    );
}

#[tokio::test]
async fn pending_forwards_remove_drops_entry() {
    let p = PendingForwards::new();
    let _rx = p.register("explicit".to_string()).await;
    assert_eq!(p.pending_count().await, 1);
    p.remove("explicit").await;
    assert_eq!(p.pending_count().await, 0);
    // Removing a missing key is a no-op (not an error).
    p.remove("ghost").await;
    assert_eq!(p.pending_count().await, 0);
}
