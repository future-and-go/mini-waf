pub mod cluster_forward;
pub mod crypto;
pub mod discovery;
pub mod election;
pub mod health;
pub mod node;
pub mod protocol;
pub mod sync;
pub mod transport;

pub use cluster_forward::PendingForwards;
pub use node::{NodeState, PeerInfo, StorageMode};
pub use protocol::ClusterMessage;
pub use waf_common::config::{ClusterConfig, NodeRole};
pub use waf_engine::RuleReloader;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::crypto::ca::CertificateAuthority;
use crate::crypto::node_cert::NodeCertificate;
use crate::election::run_election_loop;
use crate::health::{run_heartbeat_sender, run_peer_eviction};
use crate::transport::client::ClusterClient;
use crate::transport::server::ClusterServer;

/// Top-level cluster node handle.
///
/// Create with [`ClusterNode::new`] and then call [`ClusterNode::run`] inside a
/// dedicated tokio runtime (usually a background `std::thread`).
///
/// The internal `NodeState` is built eagerly in `new()` and exposed via
/// [`ClusterNode::state`] so callers (e.g. the management API) can plug the
/// SAME state into their `AppState` BEFORE the cluster is spawned. Without
/// this hand-off the API's `cluster_state` slot stays `None` and every
/// `/api/cluster/*` route returns 404 "cluster not enabled".
pub struct ClusterNode {
    config: ClusterConfig,
    node_state: Arc<NodeState>,
}

impl ClusterNode {
    /// Create a cluster node from configuration. Builds the shared `NodeState`
    /// up front so it can be handed to the API layer before `run()` consumes
    /// `self`.
    pub fn new(config: ClusterConfig) -> Result<Self> {
        let storage_mode = StorageMode::Full;
        let node_state =
            Arc::new(NodeState::new(config.clone(), storage_mode).context("failed to initialise cluster node state")?);
        Ok(Self { config, node_state })
    }

    /// Get a shared handle to this node's state. Hand this to `AppState` so
    /// `/api/cluster/status`, `/api/cluster/nodes` etc. can read role / peers /
    /// term while the cluster runs.
    pub fn state(&self) -> Arc<NodeState> {
        Arc::clone(&self.node_state)
    }

    /// Register a `RuleReloader` callback (typically the `WafEngine`) so the
    /// cluster sync layer can notify the engine when rules are replicated.
    pub fn set_rule_reloader(&self, reloader: Arc<dyn RuleReloader>) {
        self.node_state.set_rule_reloader(reloader);
    }

    /// Start the cluster node: generate or load certificates, launch QUIC server,
    /// dial seed peers, and run the heartbeat and election loops.
    ///
    /// This function does not return under normal operation.
    pub async fn run(self) -> Result<()> {
        let listen_addr: SocketAddr = self.config.listen_addr.parse().context("invalid cluster listen_addr")?;

        // ── NodeState (already built in new(); keep a local Arc for the rest
        // of this function so the existing logic compiles unchanged) ─────────
        let node_state = Arc::clone(&self.node_state);

        // ── Certificate setup ─────────────────────────────────────────────────

        let (ca_cert_der, node_cert) = if self.config.crypto.auto_generate {
            // Generate fresh CA and node certificate in-memory.
            let ca = CertificateAuthority::generate(self.config.crypto.ca_validity_days)
                .context("failed to generate cluster CA")?;
            let ca_cert_der = ca.cert_der().context("failed to DER-encode cluster CA")?;

            // Store CA private key in node state for replication to workers at join time.
            *node_state.ca_key_pem.lock() = Some(ca.key_pem().to_string());

            let node_cert = NodeCertificate::generate(&node_state.node_id, &ca, self.config.crypto.node_validity_days)
                .context("failed to generate node certificate")?;

            (ca_cert_der, node_cert)
        } else {
            // Load certificates from files (auto_generate = false).
            // This is the production path used with docker-compose or pre-provisioned certs.
            let ca_cert_path = &self.config.crypto.ca_cert;
            let ca_cert_pem = std::fs::read_to_string(ca_cert_path)
                .with_context(|| format!("failed to read CA cert from '{ca_cert_path}'"))?;
            let ca = CertificateAuthority::from_cert_pem(ca_cert_pem);
            let ca_cert_der = ca.cert_der().context("failed to DER-encode CA cert")?;

            // CA key is optional — only the main node has it.
            let ca_key_path = &self.config.crypto.ca_key;
            if !ca_key_path.is_empty() {
                match std::fs::read_to_string(ca_key_path) {
                    Ok(key_pem) => *node_state.ca_key_pem.lock() = Some(key_pem),
                    Err(e) => warn!(path = %ca_key_path, "CA key file not readable: {e}"),
                }
            }

            let node_cert_path = &self.config.crypto.node_cert;
            let node_cert_pem = std::fs::read_to_string(node_cert_path)
                .with_context(|| format!("failed to read node cert from '{node_cert_path}'"))?;
            let node_key_path = &self.config.crypto.node_key;
            let node_key_pem = std::fs::read_to_string(node_key_path)
                .with_context(|| format!("failed to read node key from '{node_key_path}'"))?;
            let node_cert = NodeCertificate::from_pem(node_cert_pem, node_key_pem);

            (ca_cert_der, node_cert)
        };

        info!(
            node_id = %node_state.node_id,
            listen = %listen_addr,
            "Cluster node starting"
        );

        // ── Dial seed peers ──────────────────────────────────────────────────

        let mut peer_senders: Vec<mpsc::Sender<ClusterMessage>> = Vec::with_capacity(self.config.seeds.len());

        for seed_str in &self.config.seeds {
            // Resolve hostname+port to SocketAddr (supports DNS names used in docker etc.)
            let Some(seed_addr) = resolve_seed_addr(seed_str).await else {
                continue;
            };

            if seed_addr == listen_addr {
                // Never dial ourselves.
                continue;
            }

            let (tx, rx) = mpsc::channel::<ClusterMessage>(256);

            // Register channel with NodeState so broadcast() reaches this peer.
            node_state.add_peer_channel(tx.clone());
            peer_senders.push(tx.clone());

            // Send JoinRequest as the initial handshake message
            let join_req = ClusterMessage::JoinRequest(crate::protocol::JoinRequest {
                token: String::new(),
                csr_pem: String::new(),
                node_info: crate::protocol::NodeInfo {
                    node_id: node_state.node_id.clone(),
                    hostname: node_state.node_id.clone(),
                    version: env!("CARGO_PKG_VERSION").to_string(),
                    listen_addr: self.config.listen_addr.clone(),
                    capabilities: vec!["waf".to_string()],
                },
            });
            if let Err(e) = tx.try_send(join_req) {
                warn!(seed = %seed_str, "Failed to queue JoinRequest: {e}");
            }

            let client = ClusterClient::new(
                seed_addr,
                node_state.node_id.clone(),
                ca_cert_der.clone(),
                node_cert.cert_pem.clone(),
                node_cert.key_pem.clone(),
            );

            let state_clone = Arc::clone(&node_state);
            tokio::spawn(async move {
                if let Err(e) = client.run_with_reconnect(state_clone, rx).await {
                    tracing::error!("Cluster client for {seed_addr} failed: {e}");
                }
            });
        }

        // ── Event batcher (worker → main) ────────────────────────────────────

        if let Some(event_rx) = node_state.take_event_rx() {
            let batch_size = self.config.sync.events_batch_size;
            let flush_interval_ms = self.config.sync.events_flush_interval_secs.saturating_mul(1000);
            let batcher =
                crate::sync::events::EventBatcher::new(node_state.node_id.clone(), batch_size, flush_interval_ms);
            let (batch_tx, mut batch_rx) = mpsc::channel::<crate::protocol::EventBatch>(64);
            tokio::spawn(async move {
                crate::sync::events::run_event_batcher(batcher, event_rx, batch_tx).await;
            });

            // Forward completed batches to all peer channels
            let state_ev = Arc::clone(&node_state);
            tokio::spawn(async move {
                while let Some(batch) = batch_rx.recv().await {
                    state_ev.broadcast(&ClusterMessage::EventBatch(batch));
                }
            });
        }

        // ── Rule sync loop (workers poll main) ────────────────────────────────

        let rules_interval = self.config.sync.rules_interval_secs;
        for tx in &peer_senders {
            let state_rs = Arc::clone(&node_state);
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                crate::sync::rules::run_rule_sync_loop(state_rs, rules_interval, tx_clone).await;
            });
        }

        // ── Config sync broadcast (main → workers) ─────────────────────────

        {
            let config_interval = self.config.sync.config_interval_secs;
            let state_cfg = Arc::clone(&node_state);
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(config_interval.max(1)));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                let mut last_broadcast_version: u64 = 0;
                loop {
                    interval.tick().await;
                    if state_cfg.current_role().await != NodeRole::Main {
                        continue;
                    }
                    let config_version = *state_cfg.config_version.read().await;
                    if config_version > last_broadcast_version {
                        let syncable = crate::sync::config::SyncableConfig {
                            proxy: Default::default(),
                            rules: Default::default(),
                            cache: Default::default(),
                            api: Default::default(),
                        };
                        let mut syncer = crate::sync::config::ConfigSyncer::new(state_cfg.node_id.clone());
                        if let Ok(msg) = syncer.build_sync(&syncable) {
                            state_cfg.broadcast(&ClusterMessage::ConfigSync(msg));
                            last_broadcast_version = config_version;
                        }
                    }
                }
            });
        }

        // ── Heartbeat sender ─────────────────────────────────────────────────

        if !peer_senders.is_empty() {
            let state_hb = Arc::clone(&node_state);
            let interval_ms = self.config.election.heartbeat_interval_ms;
            tokio::spawn(async move {
                run_heartbeat_sender(state_hb, interval_ms, peer_senders).await;
            });
        }

        // ── Peer eviction (dead-peer cleanup) ─────────────────────────────────

        {
            let eviction_state = Arc::clone(&node_state);
            // Check 3x the heartbeat interval — gives peers enough time to respond
            // before being declared dead by the phi-accrual detector.
            let eviction_interval_ms = self.config.election.heartbeat_interval_ms.saturating_mul(3);
            tokio::spawn(async move {
                run_peer_eviction(eviction_state, eviction_interval_ms).await;
            });
        }

        // ── Election loop ────────────────────────────────────────────────────

        let state_election = Arc::clone(&node_state);
        tokio::spawn(async move {
            run_election_loop(state_election).await;
        });

        // ── QUIC server (blocks) ─────────────────────────────────────────────

        let server = ClusterServer::new(listen_addr, ca_cert_der, node_cert.cert_pem, node_cert.key_pem);

        server.serve(node_state).await
    }
}

/// Resolve a seed address string (hostname:port or ip:port) to a `SocketAddr`.
///
/// Returns `None` and logs a warning if resolution fails or yields no addresses.
async fn resolve_seed_addr(seed_str: &str) -> Option<SocketAddr> {
    match tokio::net::lookup_host(seed_str).await {
        Ok(mut addrs) => addrs.next().or_else(|| {
            warn!(addr = %seed_str, "Cluster seed resolved to no addresses; skipping");
            None
        }),
        Err(e) => {
            warn!(addr = %seed_str, error = %e, "Cannot resolve cluster seed address; skipping");
            None
        }
    }
}
