//! Phase 05: pure-data types in cache::backend (BackendHealth, CachedResponse).

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

use bytes::Bytes;

use gateway::cache::backend::{BackendHealth, CachedResponse};

#[test]
fn backend_health_healthy_constructor_zero_error() {
    let h = BackendHealth::healthy(123);
    assert!(h.ok);
    assert_eq!(h.latency_us, 123);
    assert!(h.error.is_none());
}

#[test]
fn backend_health_unhealthy_carries_error_and_zero_latency() {
    let h = BackendHealth::unhealthy("connection refused");
    assert!(!h.ok);
    assert_eq!(h.latency_us, 0);
    assert_eq!(h.error.as_deref(), Some("connection refused"));
}

#[test]
fn backend_health_unhealthy_accepts_string() {
    let owned = String::from("timeout");
    let h = BackendHealth::unhealthy(owned);
    assert_eq!(h.error.as_deref(), Some("timeout"));
}

#[test]
fn cached_response_constructible_with_all_fields() {
    let r = CachedResponse {
        status: 200,
        headers: vec![("content-type".into(), "text/html".into())],
        body: Bytes::from_static(b"<html/>"),
        max_age: 60,
    };
    let cloned = r.clone();
    assert_eq!(cloned.status, 200);
    assert_eq!(cloned.headers.len(), 1);
    assert_eq!(cloned.body.len(), 7);
    assert_eq!(cloned.max_age, 60);
}
