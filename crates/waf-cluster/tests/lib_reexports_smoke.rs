//! Smoke test that touches the top-level re-exports from lib.rs and the
//! `resolve_seed_addr` helper used by `ClusterNode::run`.
//!
//! Constructs a `ClusterNode` (cheap — no network) and reads its handle so the
//! re-exported types and the constructor count toward coverage.
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

use std::net::SocketAddr;
use std::time::Duration;

use waf_cluster::{ClusterConfig, ClusterMessage, ClusterNode, NodeRole, NodeState, PendingForwards, StorageMode};
use waf_common::config::ClusterCryptoConfig;

fn loopback() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("local_addr")
}

#[test]
fn cluster_node_constructor_exposes_state() {
    let cfg = ClusterConfig {
        enabled: true,
        node_id: "smoke".to_string(),
        listen_addr: loopback().to_string(),
        ..ClusterConfig::default()
    };
    let node = ClusterNode::new(cfg).expect("new");
    let state = node.state();
    assert_eq!(state.node_id, "smoke");
}

#[test]
fn pending_forwards_default_is_empty() {
    let p = PendingForwards::default();
    let _ = p.clone();
}

#[tokio::test]
async fn re_exported_node_state_usable() {
    let cfg = ClusterConfig {
        enabled: true,
        node_id: "smoke2".to_string(),
        listen_addr: loopback().to_string(),
        role: "main".to_string(),
        ..ClusterConfig::default()
    };
    let node = std::sync::Arc::new(NodeState::new(cfg, StorageMode::Full).expect("ns"));
    assert_eq!(node.current_role().await, NodeRole::Main);
}

#[test]
fn re_exported_message_variants_constructable() {
    let m = ClusterMessage::NodeLeave { node_id: "n".into() };
    let s = serde_json::to_string(&m).expect("ser");
    assert!(s.contains("node_leave"));
}

#[tokio::test]
async fn cluster_node_run_invalid_listen_addr_errors() {
    let cfg = ClusterConfig {
        enabled: true,
        node_id: "bad".to_string(),
        listen_addr: "not-an-addr".to_string(),
        ..ClusterConfig::default()
    };
    let node = ClusterNode::new(cfg).expect("new");
    let res = node.run().await;
    let msg = match res {
        Ok(()) => panic!("bad addr must error"),
        Err(e) => format!("{e}"),
    };
    assert!(msg.contains("invalid cluster listen_addr"));
}

#[tokio::test]
async fn cluster_node_run_auto_generate_drives_full_setup() {
    // Install crypto provider for QUIC.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let addr = loopback();
    let cfg = ClusterConfig {
        enabled: true,
        node_id: "full-run".to_string(),
        listen_addr: addr.to_string(),
        seeds: vec!["127.0.0.1:1".to_string(), "definitely-not-a-host:9999".to_string()],
        crypto: ClusterCryptoConfig {
            auto_generate: true,
            ..ClusterCryptoConfig::default()
        },
        ..ClusterConfig::default()
    };
    let node = ClusterNode::new(cfg).expect("new");
    let h = tokio::spawn(async move { node.run().await });
    tokio::time::sleep(Duration::from_millis(400)).await;
    h.abort();
    let _ = h.await;
}

#[tokio::test]
async fn cluster_node_run_load_certs_missing_file_errors() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let addr = loopback();
    let cfg = ClusterConfig {
        enabled: true,
        node_id: "load-fail".to_string(),
        listen_addr: addr.to_string(),
        crypto: ClusterCryptoConfig {
            auto_generate: false,
            ca_cert: "/nonexistent/ca.pem".to_string(),
            ca_key: String::new(),
            node_cert: "/nonexistent/node.pem".to_string(),
            node_key: "/nonexistent/node.key".to_string(),
            ..ClusterCryptoConfig::default()
        },
        ..ClusterConfig::default()
    };
    let node = ClusterNode::new(cfg).expect("new");
    let res = node.run().await;
    let msg = match res {
        Ok(()) => panic!("missing cert files must error"),
        Err(e) => format!("{e}"),
    };
    assert!(msg.contains("failed to read CA cert"), "msg = {msg}");
}
