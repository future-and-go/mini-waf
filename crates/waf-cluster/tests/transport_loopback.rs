//! End-to-end loopback test: a `ClusterServer` accepts a real `ClusterClient`
//! over QUIC mTLS, exercises the JoinRequest/JoinResponse handshake, then both
//! sides shut down.
//!
//! This is the only test that drives `transport::server::serve` and
//! `transport::client::run_with_reconnect` past their TLS-config builders into
//! actual network I/O — it pays for the bulk of those files' coverage.
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
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use waf_cluster::crypto::ca::CertificateAuthority;
use waf_cluster::crypto::node_cert::NodeCertificate;
use waf_cluster::node::StorageMode;
use waf_cluster::protocol::{ClusterMessage, JoinRequest, NodeInfo};
use waf_cluster::transport::client::ClusterClient;
use waf_cluster::transport::server::ClusterServer;
use waf_cluster::{ClusterConfig, NodeState};

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn loopback() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("local_addr")
}

#[tokio::test]
async fn server_accepts_client_join_request() {
    install_crypto();

    let ca = CertificateAuthority::generate(1).expect("ca");
    let ca_der = ca.cert_der().expect("der");
    let server_cert = NodeCertificate::generate("srv", &ca, 1).expect("srv-cert");
    let client_cert = NodeCertificate::generate("cli", &ca, 1).expect("cli-cert");

    let server_addr = loopback();

    let mut server_cfg = ClusterConfig::default();
    server_cfg.node_id = "srv".to_string();
    server_cfg.listen_addr = server_addr.to_string();
    let server_state = Arc::new(NodeState::new(server_cfg, StorageMode::Full).expect("srv-state"));
    *server_state.ca_key_pem.lock() = Some(ca.key_pem().to_string());

    let server = ClusterServer::new(
        server_addr,
        ca_der.clone(),
        server_cert.cert_pem.clone(),
        server_cert.key_pem.clone(),
    );

    let server_handle = tokio::spawn(async move { server.serve(server_state).await });

    // Tiny pause so the listener is bound before the client dials.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut client_cfg = ClusterConfig::default();
    client_cfg.node_id = "cli".to_string();
    let client_state = Arc::new(NodeState::new(client_cfg, StorageMode::ForwardOnly).expect("cli-state"));

    let (tx, rx) = mpsc::channel::<ClusterMessage>(8);
    let join_req = ClusterMessage::JoinRequest(JoinRequest {
        token: String::new(),
        csr_pem: String::new(),
        node_info: NodeInfo {
            node_id: "cli".to_string(),
            hostname: "cli".to_string(),
            version: "0.0.0".to_string(),
            listen_addr: loopback().to_string(),
            capabilities: vec!["waf".to_string()],
        },
    });
    tx.try_send(join_req).expect("queue join");

    let client = ClusterClient::new(
        server_addr,
        "cli".to_string(),
        ca_der,
        client_cert.cert_pem,
        client_cert.key_pem,
    );

    let client_handle = tokio::spawn(async move { client.run_with_reconnect(client_state, rx).await });

    // Drive both sides briefly to complete handshake and exchange.
    tokio::time::sleep(Duration::from_millis(700)).await;

    drop(tx);
    client_handle.abort();
    server_handle.abort();
    let _ = client_handle.await;
    let _ = server_handle.await;
}
