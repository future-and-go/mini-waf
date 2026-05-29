use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::debug;
use waf_common::config::NodeRole;
use waf_engine::{Rule, RuleRegistry, RuleReloader};

use crate::node::NodeState;
use crate::protocol::{ChangeOp, ClusterMessage, RuleChange, RuleSyncRequest, RuleSyncResponse, SyncType};

/// Ring-buffer of recent rule changes maintained by the main node.
///
/// Workers send `RuleSyncRequest { current_version }` and receive either an
/// incremental delta (if the worker is caught up enough) or a full snapshot.
pub struct RuleChangelog {
    /// (`version_after_change`, change) pairs in chronological order
    changes: VecDeque<(u64, RuleChange)>,
    max_retained: usize,
    /// Monotonic version counter — incremented by every `record_change` call.
    current_version: u64,
}

impl RuleChangelog {
    /// Create a new changelog with the given ring-buffer capacity.
    pub const fn new(max_retained: usize) -> Self {
        Self {
            changes: VecDeque::new(),
            max_retained,
            current_version: 0,
        }
    }

    /// The version after the last recorded change.
    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    /// Record a rule change, incrementing the internal version counter.
    ///
    /// `rule` is `None` for `Delete` operations.
    pub fn record_change(&mut self, op: ChangeOp, rule_id: String, rule: Option<&Rule>) {
        self.current_version += 1;
        let version = self.current_version;
        let rule_json = rule.and_then(|r| serde_json::to_value(r).ok());
        let change = RuleChange { op, rule_id, rule_json };
        self.push(version, change);
    }

    /// Append a pre-built change entry at the given version.
    pub fn push(&mut self, version: u64, change: RuleChange) {
        if self.changes.len() >= self.max_retained {
            self.changes.pop_front();
        }
        self.changes.push_back((version, change));
    }

    /// Return all changes with `version > from_version`, or `None` when the
    /// worker is too far behind (its version precedes the oldest buffered entry).
    pub fn delta_since(&self, from_version: u64) -> Option<Vec<RuleChange>> {
        if self.changes.is_empty() {
            // No changes ever recorded; worker is already up to date.
            return Some(Vec::new());
        }
        let first = self.changes.front().map_or(0, |(v, _)| *v);
        if from_version < first {
            // Worker is too far behind; needs a full snapshot.
            return None;
        }
        Some(
            self.changes
                .iter()
                .filter(|(v, _)| *v > from_version)
                .map(|(_, c)| c.clone())
                .collect(),
        )
    }

    /// Build a `RuleSyncResponse` for a worker's sync request.
    ///
    /// Returns an `Incremental` response when possible.  For `Full` responses
    /// the `snapshot_lz4` field is left empty — callers must call
    /// [`handle_sync_request`] or fill it manually.
    pub fn build_response(&self, from_version: u64) -> RuleSyncResponse {
        self.delta_since(from_version).map_or_else(
            || RuleSyncResponse {
                version: self.current_version,
                sync_type: SyncType::Full,
                changes: Vec::new(),
                snapshot_lz4: Vec::new(),
            },
            |changes| RuleSyncResponse {
                version: self.current_version,
                sync_type: SyncType::Incremental,
                changes,
                snapshot_lz4: Vec::new(),
            },
        )
    }
}

// ─── Snapshot helpers ──────────────────────────────────────────────────────────

/// Serialize and lz4-compress a rule slice for transmission as a full snapshot.
pub fn snapshot_rules(rules: &[Rule]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(rules).context("failed to serialize rules to JSON")?;
    Ok(lz4_flex::compress_prepend_size(&json))
}

/// Decompress and deserialize a full snapshot produced by [`snapshot_rules`].
pub fn restore_snapshot(data: &[u8]) -> Result<Vec<Rule>> {
    let json = lz4_flex::decompress_size_prepended(data).map_err(|e| anyhow::anyhow!("lz4 decompress failed: {e}"))?;
    serde_json::from_slice(&json).context("failed to deserialize rules from snapshot")
}

// ─── Main-side handler ─────────────────────────────────────────────────────────

/// Respond to a worker's `RuleSyncRequest`.
///
/// Sends incremental changes when the worker is close enough; falls back to a
/// full lz4-compressed snapshot when the worker is too far behind or is new.
///
/// `rules` is the current authoritative rule list on the main node.
pub fn handle_sync_request(
    changelog: &RuleChangelog,
    request: &RuleSyncRequest,
    rules: &[Rule],
) -> Result<RuleSyncResponse> {
    let mut response = changelog.build_response(request.current_version);
    if matches!(response.sync_type, SyncType::Full) {
        response.snapshot_lz4 = snapshot_rules(rules)?;
    }
    Ok(response)
}

// ─── Worker-side appliers ──────────────────────────────────────────────────────

/// Apply an incremental list of rule changes to a local registry.
///
/// `Upsert` changes deserialize the embedded JSON and insert the rule.
/// `Delete` changes remove the rule by id.
pub fn apply_rule_changes(registry: &mut RuleRegistry, changes: Vec<RuleChange>) -> Result<()> {
    for change in changes {
        match change.op {
            ChangeOp::Delete => {
                registry.remove(&change.rule_id);
            }
            ChangeOp::Upsert => {
                if let Some(val) = change.rule_json {
                    let rule: Rule =
                        serde_json::from_value(val).context("failed to deserialize rule from incremental change")?;
                    registry.insert(rule);
                }
            }
        }
    }
    Ok(())
}

/// Replace the entire local registry with rules from a full snapshot.
///
/// Clears the existing registry before inserting the deserialized rules so
/// that any rules deleted on the main node are also removed locally.
pub fn apply_full_snapshot(registry: &mut RuleRegistry, data: &[u8]) -> Result<()> {
    let rules = restore_snapshot(data)?;
    registry.clear();
    for rule in rules {
        registry.insert(rule);
    }
    Ok(())
}

/// Apply a `RuleSyncResponse` received from the main node to a local registry.
///
/// * `Incremental` — applies the embedded change list to the existing registry.
/// * `Full` — decompresses the lz4 snapshot, clears the registry, and reloads
///   all rules from scratch.
///
/// In both cases the registry version is set to the authoritative value carried
/// by the response, and `reloader.on_rules_updated()` is called so the engine
/// can react (e.g., hot-reload pattern matchers).
pub async fn apply_sync_response(
    response: RuleSyncResponse,
    registry: &mut RuleRegistry,
    reloader: &dyn RuleReloader,
) -> Result<()> {
    apply_sync_response_sync(response, registry)?;
    reloader.on_rules_updated(registry.version).await
}

/// Synchronous variant of [`apply_sync_response`] that mutates the registry
/// without calling the reloader. Callers must trigger engine notification
/// separately (e.g. via `NodeState::notify_rules_updated`).
pub fn apply_sync_response_sync(response: RuleSyncResponse, registry: &mut RuleRegistry) -> Result<()> {
    let version = response.version;
    match response.sync_type {
        SyncType::Incremental => {
            apply_rule_changes(registry, response.changes)?;
        }
        SyncType::Full => {
            apply_full_snapshot(registry, &response.snapshot_lz4)?;
        }
    }
    registry.version = version;
    Ok(())
}

// ─── Low-level compression helpers (kept for compatibility) ───────────────────

/// Compress a raw byte slice using lz4 with prepended original size.
pub fn compress_snapshot(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an lz4-compressed blob produced by [`compress_snapshot`].
pub fn decompress_snapshot(data: &[u8]) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data).map_err(|e| anyhow::anyhow!("lz4 decompress failed: {e}"))
}

// ─── Rule sync loop (worker → main) ─────────────────────────────────────────

/// Periodically send `RuleSyncRequest` to the main node and apply responses.
///
/// Only active when the node's role is `Worker`. Exits when `main_tx` is closed.
///
/// An initial random jitter sleep of up to one interval is applied before the
/// first tick so that all workers in a cluster do not poll the main node in
/// a thundering-herd burst on startup.
pub async fn run_rule_sync_loop(state: Arc<NodeState>, interval_secs: u64, main_tx: mpsc::Sender<ClusterMessage>) {
    let interval_ms = interval_secs.max(1) * 1000;
    let jitter_ms = rand::random::<u64>() % interval_ms;
    tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    loop {
        interval.tick().await;
        if state.current_role().await != NodeRole::Worker {
            continue;
        }
        let version = *state.rules_version.read().await;
        let req = ClusterMessage::RuleSyncRequest(RuleSyncRequest {
            current_version: version,
        });
        if main_tx.send(req).await.is_err() {
            debug!("Rule sync loop: main channel closed, stopping");
            return;
        }
    }
}

/// No-op reloader for contexts where the engine is not available.
pub struct NoopReloader;

#[async_trait::async_trait]
impl RuleReloader for NoopReloader {
    async fn on_rules_updated(&self, _version: u64) -> Result<()> {
        Ok(())
    }
    async fn reload_from_registry(&self, _registry: &RuleRegistry) -> Result<()> {
        Ok(())
    }
}
