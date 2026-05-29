//! Integration test for the `X-Forwarded-By` cluster peer audit header.
//!
//! Verifies that `forward_write` stamps the worker's `local_node_id` into
//! the outgoing `ApiForward.headers` map as the LAST write before the QUIC
//! send, so it cannot be silently dropped or overwritten by any prior
//! header-mutation pass on the worker side. The trust-model rationale is
//! documented in `docs/cluster-protocol.md` §7 "Peer Trust Model".
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods
)]

use std::collections::HashMap;

use tokio::sync::mpsc;

use waf_cluster::cluster_forward::{PendingForwards, X_FORWARDED_BY, forward_write};
use waf_cluster::protocol::{ApiForwardResponse, ClusterMessage};

const TEST_NODE_ID: &str = "worker-node-7";

#[tokio::test]
async fn forward_write_stamps_x_forwarded_by_header() {
    let pending = PendingForwards::new();
    let (tx, mut rx) = mpsc::channel::<ClusterMessage>(8);
    let pending_clone = pending.clone();

    let handle = tokio::spawn(async move {
        forward_write(
            &tx,
            &pending_clone,
            TEST_NODE_ID,
            "audit-req-1".to_string(),
            "POST".to_string(),
            "/v1/rules".to_string(),
            b"payload".to_vec(),
            HashMap::new(),
            5_000,
        )
        .await
    });

    let outgoing = rx.recv().await.expect("forward message queued");
    match outgoing {
        ClusterMessage::ApiForward(fw) => {
            let stamped = fw
                .headers
                .get(X_FORWARDED_BY)
                .expect("X-Forwarded-By must be stamped on every forward");
            assert_eq!(stamped, TEST_NODE_ID);
        }
        other => panic!("expected ApiForward, got {other:?}"),
    }

    pending
        .resolve(ApiForwardResponse {
            request_id: "audit-req-1".to_string(),
            status: 200,
            body: Vec::new(),
        })
        .await;
    let _ = handle.await.expect("join").expect("forward ok");
}

#[tokio::test]
async fn forward_write_stamp_overrides_caller_supplied_header() {
    // If a caller passes a stale or spoofed X-Forwarded-By in the headers
    // map, the worker's own node_id MUST win — the stamp is the last write
    // before send so any caller-side value is replaced. This is what makes
    // the audit header trustworthy for traceability on Main.
    let pending = PendingForwards::new();
    let (tx, mut rx) = mpsc::channel::<ClusterMessage>(8);
    let pending_clone = pending.clone();

    let mut headers = HashMap::new();
    headers.insert(X_FORWARDED_BY.to_string(), "spoofed-other-node".to_string());
    headers.insert("authorization".to_string(), "Bearer test".to_string());

    let handle = tokio::spawn(async move {
        forward_write(
            &tx,
            &pending_clone,
            TEST_NODE_ID,
            "audit-req-2".to_string(),
            "PUT".to_string(),
            "/v1/config".to_string(),
            Vec::new(),
            headers,
            5_000,
        )
        .await
    });

    let outgoing = rx.recv().await.expect("forward message queued");
    match outgoing {
        ClusterMessage::ApiForward(fw) => {
            assert_eq!(
                fw.headers.get(X_FORWARDED_BY).map(String::as_str),
                Some(TEST_NODE_ID),
                "stamp must overwrite caller-supplied X-Forwarded-By"
            );
            // Other caller-supplied headers are passed through unchanged —
            // the stamp is targeted, not a wholesale replace.
            assert_eq!(fw.headers.get("authorization").map(String::as_str), Some("Bearer test"));
        }
        other => panic!("expected ApiForward, got {other:?}"),
    }

    pending
        .resolve(ApiForwardResponse {
            request_id: "audit-req-2".to_string(),
            status: 200,
            body: Vec::new(),
        })
        .await;
    let _ = handle.await.expect("join").expect("forward ok");
}
