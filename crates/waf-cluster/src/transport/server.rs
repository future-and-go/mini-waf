//! QUIC mTLS listener for cluster communication.
//!
//! Reuses the same quinn + rustls pattern from gateway/http3.rs, with the
//! addition of `WebPkiClientVerifier` to require and verify peer certificates
//! against the cluster CA.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use quinn::Connection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use tracing::{debug, info, warn};

use crate::node::NodeState;
use crate::protocol::ClusterMessage;
use crate::transport::frame;

/// QUIC mTLS server for cluster communication.
pub struct ClusterServer {
    listen_addr: SocketAddr,
    /// DER-encoded cluster CA certificate (added to client verifier root store)
    ca_cert_der: CertificateDer<'static>,
    /// Node certificate chain (PEM) presented to connecting peers
    node_cert_pem: String,
    /// Node private key (PEM) — never log
    node_key_pem: String,
}

impl ClusterServer {
    /// Create a new cluster server.
    pub fn new(
        listen_addr: SocketAddr,
        ca_cert_der: CertificateDer<'static>,
        node_cert_pem: String,
        node_key_pem: String,
    ) -> Self {
        Self {
            listen_addr,
            ca_cert_der,
            node_cert_pem,
            node_key_pem,
        }
    }

    /// Build the rustls `ServerConfig` with mTLS client cert verification.
    fn build_tls_config(&self) -> Result<rustls::ServerConfig> {
        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add(self.ca_cert_der.clone())
            .context("failed to add CA cert to root store")?;

        let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
            .build()
            .context("failed to build client cert verifier")?;

        let certs: Vec<CertificateDer<'static>> =
            rustls_pemfile::certs(&mut self.node_cert_pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .context("failed to parse node cert PEM")?;

        let key: PrivateKeyDer<'static> =
            rustls_pemfile::private_key(&mut self.node_key_pem.as_bytes())
                .context("failed to read node key PEM")?
                .context("no private key found in node key PEM")?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(certs, key)
            .context("invalid node TLS certificate or key")?;

        tls_config.alpn_protocols = vec![b"prx-cluster/1".to_vec()];

        Ok(tls_config)
    }

    /// Start accepting inbound QUIC connections from peer nodes.
    ///
    /// Runs forever; returns only on fatal error.
    pub async fn serve(self, node_state: Arc<NodeState>) -> Result<()> {
        let tls_config = self.build_tls_config()?;
        let quic_config =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
                .map_err(|e| anyhow::anyhow!("QUIC server TLS config error: {e:?}"))?;
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

        let endpoint = quinn::Endpoint::server(server_config, self.listen_addr)
            .context("failed to bind QUIC cluster endpoint")?;

        info!(addr = %self.listen_addr, "Cluster QUIC mTLS server listening");

        while let Some(incoming) = endpoint.accept().await {
            let state = Arc::clone(&node_state);
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        if let Err(e) = handle_peer_connection(conn, state).await {
                            warn!("Cluster peer connection error: {e}");
                        }
                    }
                    Err(e) => warn!("QUIC cluster accept error: {e}"),
                }
            });
        }

        Ok(())
    }

    /// Returns the configured listen address.
    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

/// Handle a single authenticated peer connection.
async fn handle_peer_connection(conn: Connection, node_state: Arc<NodeState>) -> Result<()> {
    let peer = conn.remote_address();
    debug!(%peer, "Cluster peer connected");

    loop {
        match conn.accept_bi().await {
            Ok((mut send, mut recv)) => {
                let state = Arc::clone(&node_state);
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(&mut send, &mut recv, state).await {
                        debug!("Cluster stream closed: {e}");
                    }
                });
            }
            Err(quinn::ConnectionError::ApplicationClosed(_)) => {
                debug!(%peer, "Cluster peer disconnected gracefully");
                break;
            }
            Err(e) => {
                debug!(%peer, "Cluster connection error: {e}");
                break;
            }
        }
    }

    Ok(())
}

/// Read and process messages from a single bidirectional stream.
async fn handle_stream(
    _send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    node_state: Arc<NodeState>,
) -> Result<()> {
    loop {
        let msg: ClusterMessage = frame::read_frame(recv).await?;
        dispatch_message(msg, &node_state).await;
    }
}

/// Route an inbound cluster message to the appropriate handler.
async fn dispatch_message(msg: ClusterMessage, node_state: &NodeState) {
    match msg {
        ClusterMessage::Heartbeat(hb) => {
            debug!(
                from = %hb.node_id,
                seq = hb.sequence,
                role = ?hb.role,
                "Heartbeat received"
            );
            let now_ms = unix_ms();
            let mut peers = node_state.peers.write().await;
            if let Some(peer) = peers.iter_mut().find(|p| p.node_id == hb.node_id) {
                peer.last_seen_ms = now_ms;
            }
        }
        ClusterMessage::JoinRequest(req) => {
            debug!(from = %req.node_info.node_id, "JoinRequest received (handled in P3)");
        }
        ClusterMessage::ElectionVote(vote) => {
            debug!(candidate = %vote.candidate_id, term = vote.term, "ElectionVote received");
        }
        ClusterMessage::ElectionResult(result) => {
            debug!(elected = %result.elected_id, term = result.term, "ElectionResult received");
        }
        other => {
            debug!(msg_type = ?std::mem::discriminant(&other), "Unhandled cluster message");
        }
    }
}

fn unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
