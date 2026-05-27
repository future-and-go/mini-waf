//! Write forwarding tests — forward flow, timeout, pending resolution.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

use waf_cluster::cluster_forward::{PendingForwards, forward_write, is_write_method};
use waf_cluster::protocol::{ApiForwardResponse, ClusterMessage};

#[test]
fn is_write_method_identifies_mutating_methods() {
    assert!(is_write_method("POST"));
    assert!(is_write_method("PUT"));
    assert!(is_write_method("DELETE"));
    assert!(is_write_method("PATCH"));
    assert!(is_write_method("post"));
    assert!(is_write_method("Post"));

    assert!(!is_write_method("GET"));
    assert!(!is_write_method("HEAD"));
    assert!(!is_write_method("OPTIONS"));
    assert!(!is_write_method("get"));
}

#[tokio::test]
async fn pending_forwards_register_and_resolve() {
    let pending = PendingForwards::new();

    let rx = pending.register("req-1".to_string()).await;

    let response = ApiForwardResponse {
        request_id: "req-1".to_string(),
        status: 201,
        body: b"created".to_vec(),
    };
    pending.resolve(response).await;

    let result = rx.await.unwrap();
    assert_eq!(result.status, 201);
    assert_eq!(result.body, b"created");
    assert_eq!(pending.pending_count().await, 0);
}

#[tokio::test]
async fn pending_forwards_resolve_unknown_id_logs_warning() {
    let pending = PendingForwards::new();

    // Resolving unknown ID should not panic
    let response = ApiForwardResponse {
        request_id: "unknown".to_string(),
        status: 200,
        body: vec![],
    };
    pending.resolve(response).await;
    assert_eq!(pending.pending_count().await, 0);
}

#[tokio::test]
async fn pending_forwards_cancel_all() {
    let pending = PendingForwards::new();

    let rx1 = pending.register("req-1".to_string()).await;
    let rx2 = pending.register("req-2".to_string()).await;
    assert_eq!(pending.pending_count().await, 2);

    pending.cancel_all().await;
    assert_eq!(pending.pending_count().await, 0);

    // Receivers should get errors (senders dropped)
    assert!(rx1.await.is_err());
    assert!(rx2.await.is_err());
}

#[tokio::test]
async fn forward_write_sends_api_forward_message() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<ClusterMessage>(16);
    let pending = PendingForwards::new();

    let mut headers = HashMap::new();
    headers.insert("Content-Type".to_string(), "application/json".to_string());

    let handle = tokio::spawn(async move {
        forward_write(
            &tx,
            &pending,
            "req-42".to_string(),
            "POST".to_string(),
            "/api/rules".to_string(),
            b"{}".to_vec(),
            headers,
            100,
        )
        .await
    });

    // Receive the forwarded message
    let msg = rx.recv().await.unwrap();
    match msg {
        ClusterMessage::ApiForward(fwd) => {
            assert_eq!(fwd.request_id, "req-42");
            assert_eq!(fwd.method, "POST");
            assert_eq!(fwd.path, "/api/rules");
            assert_eq!(fwd.body, b"{}");
        }
        other => panic!("Expected ApiForward, got {other:?}"),
    }

    // Handle will time out since we never send a response
    let result = handle.await.unwrap();
    assert!(result.is_err());
}

#[tokio::test]
async fn forward_write_timeout_returns_error() {
    let (tx, _rx) = tokio::sync::mpsc::channel::<ClusterMessage>(16);
    let pending = PendingForwards::new();

    let result = forward_write(
        &tx,
        &pending,
        "req-timeout".to_string(),
        "POST".to_string(),
        "/api/test".to_string(),
        vec![],
        HashMap::new(),
        50, // 50ms timeout
    )
    .await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("timed out"));
}

#[tokio::test]
async fn forward_write_channel_closed_returns_error() {
    let (tx, rx) = tokio::sync::mpsc::channel::<ClusterMessage>(1);
    drop(rx); // Close the channel immediately

    let pending = PendingForwards::new();
    let result = forward_write(
        &tx,
        &pending,
        "req-closed".to_string(),
        "DELETE".to_string(),
        "/api/hosts/1".to_string(),
        vec![],
        HashMap::new(),
        1000,
    )
    .await;

    assert!(result.is_err());
    let err_msg = format!("{}", result.unwrap_err());
    assert!(err_msg.contains("outbound channel closed"));
}
