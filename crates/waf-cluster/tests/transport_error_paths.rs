//! Transport-layer error paths: frame codec edge cases and TLS-config failures.
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

use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio::time::Duration;

use waf_cluster::crypto::ca::CertificateAuthority;
use waf_cluster::crypto::node_cert::NodeCertificate;
use waf_cluster::node::StorageMode;
use waf_cluster::protocol::{ClusterMessage, Heartbeat};
use waf_cluster::transport::client::ClusterClient;
use waf_cluster::transport::frame::{read_frame, write_frame};
use waf_cluster::transport::server::ClusterServer;
use waf_cluster::{ClusterConfig, NodeState};
use waf_common::config::NodeRole;

fn install_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn loopback() -> SocketAddr {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind");
    s.local_addr().expect("local_addr")
}

// ─── Frame roundtrip and oversize / truncation handling ──────────────────────

#[tokio::test]
async fn frame_roundtrip_heartbeat() {
    let msg = ClusterMessage::Heartbeat(Heartbeat {
        sequence: 7,
        timestamp_ms: 1234,
        node_id: "n".to_string(),
        role: NodeRole::Worker,
        uptime_secs: 1,
        cpu_percent: 0.1,
        memory_used_bytes: 256,
        total_requests: 9,
        blocked_requests: 1,
        rules_version: 2,
        config_version: 3,
    });
    let mut buf: Vec<u8> = Vec::new();
    write_frame(&mut buf, &msg).await.expect("write_frame");

    let mut reader = std::io::Cursor::new(buf);
    let decoded: ClusterMessage = read_frame(&mut reader).await.expect("read_frame");
    match decoded {
        ClusterMessage::Heartbeat(h) => assert_eq!(h.sequence, 7),
        other => panic!("got {other:?}"),
    }
}

#[tokio::test]
async fn frame_truncated_length_prefix_errors() {
    // Only 2 bytes — read_frame needs 4 for the length.
    let buf = vec![0u8, 1u8];
    let mut reader = std::io::Cursor::new(buf);
    let res: anyhow::Result<ClusterMessage> = read_frame(&mut reader).await;
    let err = res.expect_err("must error on short length prefix");
    let msg = format!("{err}");
    assert!(msg.contains("frame length"), "msg = {msg}");
}

#[tokio::test]
async fn frame_truncated_body_errors() {
    // Length prefix says 32 bytes but body is 5 bytes.
    let mut buf = (32u32).to_be_bytes().to_vec();
    buf.extend_from_slice(b"abcde");
    let mut reader = std::io::Cursor::new(buf);
    let res: anyhow::Result<ClusterMessage> = read_frame(&mut reader).await;
    let err = res.expect_err("must error on short body");
    let msg = format!("{err}");
    assert!(msg.contains("frame body"), "msg = {msg}");
}

#[tokio::test]
async fn frame_invalid_json_errors() {
    let body = b"not-json";
    #[allow(clippy::cast_possible_truncation)]
    let len = body.len() as u32;
    let mut buf = len.to_be_bytes().to_vec();
    buf.extend_from_slice(body);
    let mut reader = std::io::Cursor::new(buf);
    let res: anyhow::Result<ClusterMessage> = read_frame(&mut reader).await;
    let err = res.expect_err("must error on bad json");
    let msg = format!("{err}");
    assert!(msg.contains("deserialize"), "msg = {msg}");
}

#[tokio::test]
async fn write_frame_to_failing_writer_errors() {
    // tokio::io::sink() succeeds — wrap a writer that errors after some bytes.
    struct ErrWriter;
    impl tokio::io::AsyncWrite for ErrWriter {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Err(std::io::Error::other("nope")))
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }
    let mut w = ErrWriter;
    let msg = ClusterMessage::NodeLeave {
        node_id: "x".to_string(),
    };
    let res = write_frame(&mut w, &msg).await;
    assert!(res.is_err(), "writer error must propagate");
    let _ = w.shutdown().await;
}

#[tokio::test]
async fn frame_large_payload_roundtrip() {
    let big = "A".repeat(4096);
    let msg = ClusterMessage::NodeLeave { node_id: big.clone() };
    let mut buf: Vec<u8> = Vec::new();
    write_frame(&mut buf, &msg).await.expect("write");
    let mut reader = std::io::Cursor::new(buf);
    let decoded: ClusterMessage = read_frame(&mut reader).await.expect("read");
    match decoded {
        ClusterMessage::NodeLeave { node_id } => assert_eq!(node_id.len(), 4096),
        other => panic!("got {other:?}"),
    }
}

// ─── ClusterClient: bad TLS cert PEM rejected at config build ───────────────

#[tokio::test]
async fn client_rejects_bad_node_cert_pem() {
    install_crypto();
    let ca = CertificateAuthority::generate(1).expect("ca");
    let ca_der = ca.cert_der().expect("der");

    let client = ClusterClient::new(
        loopback(),
        "bad-client".to_string(),
        ca_der,
        "-----BEGIN CERTIFICATE-----\nGARBAGE\n-----END CERTIFICATE-----\n".to_string(),
        "-----BEGIN PRIVATE KEY-----\nGARBAGE\n-----END PRIVATE KEY-----\n".to_string(),
    );

    let state = Arc::new(NodeState::new(ClusterConfig::default(), StorageMode::ForwardOnly).expect("ns"));
    let (tx, rx) = mpsc::channel::<ClusterMessage>(1);
    drop(tx);

    let res = tokio::time::timeout(Duration::from_millis(300), client.run_with_reconnect(state, rx)).await;
    // run_with_reconnect retries forever on TLS-config errors; we only assert it
    // does not return Ok(()).
    match res {
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(())) => panic!("must not connect cleanly with bad cert"),
    }
}

// ─── ClusterServer: getter and TLS config failures via serve() ──────────────

#[tokio::test]
async fn server_listen_addr_getter() {
    install_crypto();
    let ca = CertificateAuthority::generate(1).expect("ca");
    let ca_der = ca.cert_der().expect("der");
    let cert = NodeCertificate::generate("srv", &ca, 1).expect("nc");
    let addr = loopback();

    let server = ClusterServer::new(addr, ca_der, cert.cert_pem, cert.key_pem);
    assert_eq!(server.listen_addr(), addr);
}

#[tokio::test]
async fn server_serve_rejects_bad_cert_pem() {
    install_crypto();
    let ca = CertificateAuthority::generate(1).expect("ca");
    let ca_der: CertificateDer<'static> = ca.cert_der().expect("der");

    let server = ClusterServer::new(
        loopback(),
        ca_der,
        "-----BEGIN CERTIFICATE-----\nNOT-VALID\n-----END CERTIFICATE-----\n".to_string(),
        "-----BEGIN PRIVATE KEY-----\nNOT-VALID\n-----END PRIVATE KEY-----\n".to_string(),
    );

    let state = Arc::new(NodeState::new(ClusterConfig::default(), StorageMode::Full).expect("ns"));
    let res = server.serve(state).await;
    assert!(res.is_err(), "serve must return error for invalid cert PEM");
}

// ─── ClusterClient peer_addr getter ─────────────────────────────────────────

#[tokio::test]
async fn client_peer_addr_getter() {
    install_crypto();
    let ca = CertificateAuthority::generate(1).expect("ca");
    let ca_der = ca.cert_der().expect("der");
    let cert = NodeCertificate::generate("c", &ca, 1).expect("nc");
    let addr = loopback();
    let client = ClusterClient::new(addr, "c".to_string(), ca_der, cert.cert_pem, cert.key_pem);
    assert_eq!(client.peer_addr(), addr);
}
