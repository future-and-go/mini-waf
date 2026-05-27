//! API write request forwarding from worker nodes to the main node.
//!
//! Worker nodes operating in `ForwardOnly` storage mode cannot write to a
//! local database.  When the API layer on a worker receives a mutating HTTP
//! request (POST / PUT / DELETE / PATCH), it must forward the request to the
//! main node, await the response, and relay it back to the HTTP client.
//!
//! # Protocol
//!
//! 1. The worker generates a unique `request_id` and registers it in
//!    [`PendingForwards`].
//! 2. It sends a [`ClusterMessage::ApiForward`] to the main via the QUIC
//!    outbound channel.
//! 3. When the QUIC receive loop delivers the matching
//!    [`ClusterMessage::ApiForwardResponse`], it calls
//!    [`PendingForwards::resolve`] to wake the waiting caller.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::{Mutex, oneshot};
use tracing::{debug, warn};

use crate::protocol::{ApiForward, ApiForwardResponse, ClusterMessage};

// ─── PendingForwards ──────────────────────────────────────────────────────────

/// Registry of in-flight API forward requests waiting for a response.
///
/// Cheaply cloneable (inner state is `Arc`-wrapped).
#[derive(Clone, Default)]
pub struct PendingForwards {
    inner: Arc<Mutex<HashMap<String, oneshot::Sender<ApiForwardResponse>>>>,
}

impl PendingForwards {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a pending request.
    ///
    /// Returns a `Receiver` that resolves when the matching
    /// `ApiForwardResponse` is delivered via [`resolve`].
    pub async fn register(&self, request_id: String) -> oneshot::Receiver<ApiForwardResponse> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().await.insert(request_id, tx);
        rx
    }

    /// Deliver a response to the waiting caller.
    ///
    /// Logs a warning when no pending entry matches `response.request_id`
    /// (e.g., the caller already timed out).
    pub async fn resolve(&self, response: ApiForwardResponse) {
        let mut map = self.inner.lock().await;
        match map.remove(&response.request_id) {
            Some(tx) => {
                if tx.send(response).is_err() {
                    debug!("API forward receiver dropped before response arrived");
                }
            }
            None => {
                warn!(
                    request_id = %response.request_id,
                    "Received ApiForwardResponse with no matching pending request"
                );
            }
        }
    }

    /// Cancel all pending requests (e.g., when the QUIC connection drops).
    ///
    /// Dropping the senders causes each waiting `Receiver` to return an error,
    /// so callers can propagate the failure immediately.
    pub async fn cancel_all(&self) {
        self.inner.lock().await.clear();
    }

    /// Number of requests currently in flight.
    pub async fn pending_count(&self) -> usize {
        self.inner.lock().await.len()
    }
}

// ─── Forwarding helper ────────────────────────────────────────────────────────

/// Forward an API write request to the main node and await its response.
///
/// Sends an [`ApiForward`] message over the QUIC outbound channel and blocks
/// until the main replies with an [`ApiForwardResponse`] or the timeout
/// expires.
///
/// # Arguments
///
/// * `sender`     — QUIC outbound channel to the main node.
/// * `pending`    — Shared registry for correlating responses to requests.
/// * `request_id` — A unique identifier for this request (e.g., UUID v4).
/// * `timeout_ms` — Maximum wait time before returning an error.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn forward_write(
    sender: &tokio::sync::mpsc::Sender<ClusterMessage>,
    pending: &PendingForwards,
    request_id: String,
    method: String,
    path: String,
    body: Vec<u8>,
    headers: HashMap<String, String>,
    timeout_ms: u64,
) -> Result<ApiForwardResponse> {
    let rx = pending.register(request_id.clone()).await;

    let msg = ClusterMessage::ApiForward(ApiForward {
        request_id: request_id.clone(),
        method,
        path,
        body,
        headers,
    });

    sender
        .send(msg)
        .await
        .context("failed to queue ApiForward message; outbound channel closed")?;

    let timeout = tokio::time::Duration::from_millis(timeout_ms.max(1));
    tokio::time::timeout(timeout, rx)
        .await
        .context("API forward timed out waiting for response from main")?
        .context("API forward response channel dropped")
}

// ─── Main-side handler ────────────────────────────────────────────────────────

/// Determine whether an HTTP method is a write (mutating) operation.
///
/// Workers should forward these to the main node rather than executing locally.
pub fn is_write_method(method: &str) -> bool {
    matches!(
        method.to_ascii_uppercase().as_str(),
        "POST" | "PUT" | "DELETE" | "PATCH"
    )
}

/// Replay a forwarded API request against the local HTTP API on the main node.
///
/// Constructs an HTTP request from the `ApiForward` fields and sends it to
/// `127.0.0.1` on the API port. Returns an `ApiForwardResponse` with the status
/// and body from the local handler.
pub async fn replay_request(fwd: &ApiForward) -> ApiForwardResponse {
    let url = format!("http://127.0.0.1:9527{}", fwd.path);

    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("Failed to build HTTP client for replay: {e}");
            return ApiForwardResponse {
                request_id: fwd.request_id.clone(),
                status: 502,
                body: b"failed to build replay client".to_vec(),
            };
        }
    };

    let method = match fwd.method.to_ascii_uppercase().as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        _ => reqwest::Method::POST,
    };

    let mut builder = client.request(method, &url);
    for (key, value) in &fwd.headers {
        let lower = key.to_ascii_lowercase();
        if lower == "host" || lower == "content-length" {
            continue;
        }
        builder = builder.header(key.as_str(), value.as_str());
    }
    if !fwd.body.is_empty() {
        builder = builder.body(fwd.body.clone());
    }

    match builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default().to_vec();
            ApiForwardResponse {
                request_id: fwd.request_id.clone(),
                status,
                body,
            }
        }
        Err(e) => {
            warn!(
                request_id = %fwd.request_id,
                "Replay request to local API failed: {e}"
            );
            ApiForwardResponse {
                request_id: fwd.request_id.clone(),
                status: 502,
                body: format!("replay failed: {e}").into_bytes(),
            }
        }
    }
}
