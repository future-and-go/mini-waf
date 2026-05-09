//! Tests for the static seed discovery helper.
//!
//! Covers parse success, malformed entries, IPv4/IPv6, and duplicate handling.
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
    clippy::map_unwrap_or
)]

use waf_cluster::discovery::StaticSeeds;
use waf_common::config::ClusterConfig;

fn cfg(seeds: &[&str]) -> ClusterConfig {
    ClusterConfig {
        seeds: seeds.iter().map(|s| (*s).to_string()).collect(),
        ..ClusterConfig::default()
    }
}

#[test]
fn empty_seed_list_yields_zero_peers() {
    let s = StaticSeeds::from_config(&cfg(&[])).expect("empty list ok");
    assert!(s.peers().is_empty());
}

#[test]
fn parses_ipv4_and_ipv6() {
    let s = StaticSeeds::from_config(&cfg(&["127.0.0.1:9001", "[::1]:9002"])).expect("parse mixed");
    assert_eq!(s.peers().len(), 2);
    assert!(s.peers().iter().any(|p| p.is_ipv4()));
    assert!(s.peers().iter().any(|p| p.is_ipv6()));
}

#[test]
fn malformed_address_returns_error() {
    let res = StaticSeeds::from_config(&cfg(&["not-an-address"]));
    let msg = match res {
        Ok(_) => panic!("malformed must error"),
        Err(e) => format!("{e}"),
    };
    assert!(msg.contains("invalid seed address"), "msg = {msg}");
}

#[test]
fn missing_port_returns_error() {
    let res = StaticSeeds::from_config(&cfg(&["127.0.0.1"]));
    assert!(res.is_err(), "address without port must be rejected");
}

#[test]
fn duplicate_seeds_are_preserved() {
    // The discovery layer does not de-dup; that is the caller's responsibility.
    // This test pins the current contract.
    let s = StaticSeeds::from_config(&cfg(&["127.0.0.1:9001", "127.0.0.1:9001"])).expect("dups parse");
    assert_eq!(s.peers().len(), 2);
}
