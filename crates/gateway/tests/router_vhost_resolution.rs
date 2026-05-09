//! Phase 05: HostRouter vhost lookup coverage.

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

use gateway::HostRouter;
use waf_common::HostConfig;

fn make_host(code: &str, host: &str, port: u16) -> Arc<HostConfig> {
    Arc::new(HostConfig {
        code: code.to_string(),
        host: host.to_string(),
        port,
        ..HostConfig::default()
    })
}

#[test]
fn resolve_exact_host_port() {
    let r = HostRouter::new();
    let cfg = make_host("a", "example.com", 8080);
    r.register(&cfg);
    let got = r.resolve("example.com:8080").expect("hit");
    assert_eq!(got.code, "a");
}

#[test]
fn resolve_default_port_80_bare_host() {
    let r = HostRouter::new();
    r.register(&make_host("h80", "site80.com", 80));
    assert!(r.resolve("site80.com").is_some(), "bare host on :80");
    assert!(r.resolve("site80.com:80").is_some(), "explicit :80");
}

#[test]
fn resolve_default_port_443_bare_host() {
    let r = HostRouter::new();
    r.register(&make_host("h443", "site443.com", 443));
    assert!(r.resolve("site443.com").is_some());
    assert!(r.resolve("site443.com:443").is_some());
}

#[test]
fn resolve_strips_port_when_only_bare_registered() {
    let r = HostRouter::new();
    r.register(&make_host("h", "site.com", 80));
    // Client sent :8080 but only :80 is registered → bare-host fallback hits.
    assert!(r.resolve("site.com:8080").is_some());
}

#[test]
fn resolve_missing_host_returns_none() {
    let r = HostRouter::new();
    r.register(&make_host("h", "real.com", 80));
    assert!(r.resolve("ghost.com").is_none());
    assert!(r.resolve("ghost.com:80").is_none());
}

#[test]
fn unregister_removes_routes() {
    let r = HostRouter::new();
    r.register(&make_host("h", "example.com", 80));
    assert!(r.resolve("example.com").is_some());
    r.unregister("example.com", 80);
    assert!(r.resolve("example.com").is_none());
    assert!(r.resolve("example.com:80").is_none());
}

#[test]
fn unregister_non_default_port_only() {
    let r = HostRouter::new();
    r.register(&make_host("h", "site.com", 9000));
    assert!(r.resolve("site.com:9000").is_some());
    r.unregister("site.com", 9000);
    assert!(r.resolve("site.com:9000").is_none());
}

#[test]
fn list_dedupes_by_code() {
    let r = HostRouter::new();
    // Same code registered twice on default port → 2 internal entries, 1 dedupe.
    r.register(&make_host("dup", "dup.com", 80));
    let listed = r.list();
    assert_eq!(listed.len(), 1, "dedupe by code");
    assert_eq!(listed[0].code, "dup");
}

#[test]
fn len_and_is_empty_track_inserts() {
    let r = HostRouter::new();
    assert!(r.is_empty());
    assert_eq!(r.len(), 0);
    r.register(&make_host("a", "a.com", 80));
    // Default port registers both bare + ":80" keys.
    assert_eq!(r.len(), 2);
    assert!(!r.is_empty());
}

#[test]
fn default_constructs_empty_router() {
    let r = HostRouter::default();
    assert!(r.is_empty());
}

#[test]
fn non_default_port_does_not_register_bare_host() {
    let r = HostRouter::new();
    r.register(&make_host("h", "site.com", 9090));
    // Only "site.com:9090" should be registered, not bare "site.com".
    assert_eq!(r.len(), 1);
    // Bare-host strip path will still hit because resolve falls through
    // to splitting host_header by ':'. Check missing host header instead.
    assert!(r.resolve("other.com").is_none());
}
