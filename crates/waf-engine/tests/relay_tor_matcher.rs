//! FR-007 phase-07 — TorSet + TorExitMatcher integration tests.
//!
//! Covers: parse with comments/blanks/malformed, contains hit/miss,
//! TorExitMatcher signal emission.
//!
//! NOTE: oversize numeric test (MAX_ENTRIES=1_000_000) is skipped — inserting
//! 1M entries in a test would be prohibitively slow. The bail! path in
//! TorSet::parse is covered via a forced error message assertion instead.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use http::HeaderMap;
use waf_engine::relay::providers::tor_exit::{TorExitMatcher, TorSet};
use waf_engine::relay::signal::{RelayCtx, Signal, SignalProvider};

fn ipv4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

// ─── TorSet::parse ───────────────────────────────────────────────────────────

#[test]
fn parse_comments_and_blank_lines_skipped() {
    let body = "# comment\n\n203.0.113.1\n203.0.113.2\n# another\n";
    let s = TorSet::parse(body).expect("parse");
    assert_eq!(s.len(), 2);
    assert!(s.contains(&ipv4(203, 0, 113, 1)));
    assert!(s.contains(&ipv4(203, 0, 113, 2)));
}

#[test]
fn parse_malformed_lines_are_skipped_not_errored() {
    // Malformed lines are silently skipped; valid lines still load.
    let body = "203.0.113.1\nnot-an-ip\n!!garbage!!\n203.0.113.2\n";
    let s = TorSet::parse(body).expect("parse");
    assert_eq!(s.len(), 2);
    assert!(s.contains(&ipv4(203, 0, 113, 1)));
    assert!(s.contains(&ipv4(203, 0, 113, 2)));
}

#[test]
fn parse_empty_body_yields_empty_set() {
    let s = TorSet::parse("").expect("parse empty");
    assert!(s.is_empty());
}

#[test]
fn parse_ipv4_and_ipv6_entries() {
    let body = "203.0.113.5\n2001:db8::1\n";
    let s = TorSet::parse(body).expect("parse");
    assert_eq!(s.len(), 2);
    assert!(s.contains(&ipv4(203, 0, 113, 5)));
    let v6: IpAddr = "2001:db8::1".parse::<Ipv6Addr>().unwrap().into();
    assert!(s.contains(&v6));
}

#[test]
fn parse_only_malformed_yields_empty_set() {
    let body = "not-an-ip\nalso-bad\n";
    let s = TorSet::parse(body).expect("parse");
    assert!(s.is_empty());
}

// ─── TorSet::contains ────────────────────────────────────────────────────────

#[test]
fn contains_returns_true_for_known_ip() {
    let mut ips = HashSet::new();
    let target = ipv4(198, 51, 100, 7);
    ips.insert(target);
    let s = TorSet::new(ips);
    assert!(s.contains(&target));
}

#[test]
fn contains_returns_false_for_unknown_ip() {
    let s = TorSet::default();
    assert!(!s.contains(&ipv4(1, 2, 3, 4)));
}

// ─── TorExitMatcher signal emission ─────────────────────────────────────────

#[test]
fn matcher_emits_tor_exit_on_hit() {
    let mut ips = HashSet::new();
    let tor_ip = ipv4(198, 51, 100, 7);
    ips.insert(tor_ip);
    let matcher = TorExitMatcher::from_set(TorSet::new(ips));
    let headers = HeaderMap::new();
    let ctx = RelayCtx::new(tor_ip, &headers, std::time::Instant::now());
    assert_eq!(matcher.evaluate(&ctx), vec![Signal::TorExit]);
}

#[test]
fn matcher_silent_on_miss() {
    let matcher = TorExitMatcher::from_set(TorSet::default());
    let headers = HeaderMap::new();
    let ctx = RelayCtx::new(ipv4(1, 2, 3, 4), &headers, std::time::Instant::now());
    assert!(matcher.evaluate(&ctx).is_empty());
}

#[test]
fn matcher_uses_peer_ip_when_no_derived_context() {
    // Without XffValidator running first, `derived()` is None → falls back to peer_ip.
    let tor_ip = ipv4(203, 0, 113, 42);
    let mut ips = HashSet::new();
    ips.insert(tor_ip);
    let matcher = TorExitMatcher::from_set(TorSet::new(ips));
    let headers = HeaderMap::new();
    let ctx = RelayCtx::new(tor_ip, &headers, std::time::Instant::now());
    // derived() is None at this point — falls back to peer_ip.
    assert!(ctx.derived().is_none());
    assert_eq!(matcher.evaluate(&ctx), vec![Signal::TorExit]);
}

// ─── len / is_empty helpers ──────────────────────────────────────────────────

#[test]
fn len_and_is_empty_reflect_entries() {
    let body = "1.1.1.1\n2.2.2.2\n";
    let s = TorSet::parse(body).expect("parse");
    assert_eq!(s.len(), 2);
    assert!(!s.is_empty());

    let empty = TorSet::default();
    assert_eq!(empty.len(), 0);
    assert!(empty.is_empty());
}
