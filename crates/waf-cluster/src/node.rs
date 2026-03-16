use std::net::SocketAddr;

use anyhow::Result;
use tokio::sync::RwLock;
use tracing::info;
use waf_common::config::{ClusterConfig, NodeRole};


/// Whether this node has a live database connection or must forward writes
#[derive(Debug, Clone)]
pub enum StorageMode {
    /// Node has its own PostgreSQL connection (main, or worker with local DB)
    Full,
    /// Node has no DB — all write operations are forwarded to main
    ForwardOnly,
}

/// Known peer in the cluster
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_id: String,
    pub addr: SocketAddr,
    pub role: NodeRole,
    /// Unix timestamp (ms) of the last received heartbeat from this peer
    pub last_seen_ms: u64,
}

/// Live runtime state for this cluster node
pub struct NodeState {
    pub node_id: String,
    pub role: RwLock<NodeRole>,
    pub term: RwLock<u64>,
    pub config: ClusterConfig,
    pub peers: RwLock<Vec<PeerInfo>>,
    pub storage_mode: StorageMode,
    pub rules_version: RwLock<u64>,
    pub config_version: RwLock<u64>,
}

impl NodeState {
    /// Create a new node state from configuration
    pub fn new(config: ClusterConfig, storage_mode: StorageMode) -> Result<Self> {
        let node_id = if config.node_id.is_empty() {
            format!("node-{}", random_suffix())
        } else {
            config.node_id.clone()
        };

        let initial_role = match config.role.as_str() {
            "main" => NodeRole::Main,
            "worker" => NodeRole::Worker,
            _ => NodeRole::Worker,
        };

        info!(node_id = %node_id, role = ?initial_role, "Cluster node initialized");

        Ok(Self {
            node_id,
            role: RwLock::new(initial_role),
            term: RwLock::new(0),
            config,
            peers: RwLock::new(Vec::new()),
            storage_mode,
            rules_version: RwLock::new(0),
            config_version: RwLock::new(0),
        })
    }

    /// Read the current role without blocking
    pub async fn current_role(&self) -> NodeRole {
        *self.role.read().await
    }

    /// Transition to a new role, logging the change
    pub async fn transition_to(&self, new_role: NodeRole) {
        let mut role = self.role.write().await;
        info!(
            node_id = %self.node_id,
            from = ?*role,
            to = ?new_role,
            "Node role transition"
        );
        *role = new_role;
    }

    /// Read the current Raft term
    pub async fn current_term(&self) -> u64 {
        *self.term.read().await
    }

    /// Increment the Raft term and return the new value
    pub async fn increment_term(&self) -> u64 {
        let mut term = self.term.write().await;
        *term += 1;
        *term
    }

    /// Update rules_version and return it
    pub async fn set_rules_version(&self, version: u64) -> u64 {
        let mut rv = self.rules_version.write().await;
        *rv = version;
        version
    }

    /// Update config_version and return it
    pub async fn set_config_version(&self, version: u64) -> u64 {
        let mut cv = self.config_version.write().await;
        *cv = version;
        version
    }
}

fn random_suffix() -> String {
    format!("{:08x}", rand::random::<u32>())
}
