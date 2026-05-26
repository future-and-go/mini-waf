use std::collections::VecDeque;

use anyhow::{Context, Result};
use tracing::warn;
use waf_engine::{Rule, RuleRegistry, RuleReloader};

use crate::protocol::{ChangeOp, RuleChange, RuleSyncRequest, RuleSyncResponse, SyncType};

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

/// Upper bound on the decompressed size of an lz4 snapshot. The wire format
/// (`lz4_flex::compress_prepend_size`) carries an attacker-controlled 4-byte
/// little-endian size prefix that `lz4_flex` uses to pre-allocate the output
/// buffer. Without this cap, a malicious or compromised peer (mTLS only
/// authenticates the transport, not the payload) could ship a tiny envelope
/// claiming `u32::MAX` bytes and OOM the worker.
///
/// 32 MiB covers worst-case real rule sets (~10 MiB observed) with headroom
/// while keeping the worst-case allocation bounded.
const MAX_SNAPSHOT_BYTES: u32 = 32 * 1024 * 1024;

/// Validate the size prefix of an lz4 envelope and decompress under the cap.
///
/// Returns Err *without* touching `lz4_flex::decompress_size_prepended` when
/// the prefix is missing or claims more than [`MAX_SNAPSHOT_BYTES`], so the
/// underlying allocator never sees the attacker-supplied size.
fn decompress_with_cap(data: &[u8]) -> Result<Vec<u8>> {
    let size_bytes: [u8; 4] = data
        .get(..4)
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| anyhow::anyhow!("lz4 snapshot too short to contain size prefix"))?;
    let size = u32::from_le_bytes(size_bytes);
    if size > MAX_SNAPSHOT_BYTES {
        anyhow::bail!("lz4 snapshot decompressed size {size} exceeds {MAX_SNAPSHOT_BYTES} byte cap");
    }
    lz4_flex::decompress_size_prepended(data).map_err(|e| anyhow::anyhow!("lz4 decompress failed: {e}"))
}

/// Serialize and lz4-compress a rule slice for transmission as a full snapshot.
pub fn snapshot_rules(rules: &[Rule]) -> Result<Vec<u8>> {
    let json = serde_json::to_vec(rules).context("failed to serialize rules to JSON")?;
    Ok(lz4_flex::compress_prepend_size(&json))
}

/// Decompress and deserialize a full snapshot produced by [`snapshot_rules`].
pub fn restore_snapshot(data: &[u8]) -> Result<Vec<Rule>> {
    let json = decompress_with_cap(data)?;
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
    // Reject stale / duplicate responses before mutating registry state.
    // Out-of-order delivery (retransmit, multi-stream reorder, stale post-
    // failover main) would otherwise wipe a newer registry with an older
    // snapshot.
    if response.version <= registry.version {
        warn!(
            stale_version = response.version,
            current = registry.version,
            sync_type = ?response.sync_type,
            "stale rule sync ignored",
        );
        return Ok(());
    }
    match response.sync_type {
        SyncType::Incremental => {
            apply_rule_changes(registry, response.changes)?;
        }
        SyncType::Full => {
            apply_full_snapshot(registry, &response.snapshot_lz4)?;
        }
    }
    // Override the version accumulated by individual insert/remove calls with
    // the single authoritative version stamped by the main node.
    registry.version = response.version;
    reloader.on_rules_updated(response.version).await
}

// ─── Low-level compression helpers (kept for compatibility) ───────────────────

/// Compress a raw byte slice using lz4 with prepended original size.
pub fn compress_snapshot(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an lz4-compressed blob produced by [`compress_snapshot`].
///
/// Subject to the same [`MAX_SNAPSHOT_BYTES`] cap as [`restore_snapshot`] so
/// untrusted peers cannot weaponise the wire size prefix into an allocator
/// bomb.
pub fn decompress_snapshot(data: &[u8]) -> Result<Vec<u8>> {
    decompress_with_cap(data)
}
