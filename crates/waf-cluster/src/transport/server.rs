use std::net::SocketAddr;

use anyhow::Result;
use tracing::info;

/// QUIC mTLS listener for cluster communication.
///
/// Full implementation (quinn + rustls ServerConfig with client cert verifier)
/// is added in P1. This skeleton establishes the public API surface.
pub struct ClusterServer {
    listen_addr: SocketAddr,
}

impl ClusterServer {
    pub fn new(listen_addr: SocketAddr) -> Self {
        Self { listen_addr }
    }

    /// Start accepting inbound QUIC connections from peer nodes.
    ///
    /// Runs forever; returns only on error.
    pub async fn serve(&self) -> Result<()> {
        info!(
            addr = %self.listen_addr,
            "Cluster QUIC server ready (full mTLS implementation in P1)"
        );
        Ok(())
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}
