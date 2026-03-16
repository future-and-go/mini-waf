use std::net::SocketAddr;

use anyhow::Result;
use tracing::info;

/// QUIC mTLS dialer for outbound connections to cluster peers.
///
/// Full implementation (quinn + rustls ClientConfig with cluster CA) is added in P1.
pub struct ClusterClient {
    peer_addr: SocketAddr,
    node_id: String,
}

impl ClusterClient {
    pub fn new(peer_addr: SocketAddr, node_id: String) -> Self {
        Self { peer_addr, node_id }
    }

    /// Establish a QUIC connection to the peer and return a connected client.
    pub async fn connect(&self) -> Result<()> {
        info!(
            addr = %self.peer_addr,
            node_id = %self.node_id,
            "Connecting to cluster peer (full QUIC implementation in P1)"
        );
        Ok(())
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }
}
