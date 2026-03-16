use std::collections::VecDeque;

use anyhow::Result;

use crate::protocol::{RuleChange, RuleSyncResponse, SyncType};

/// Ring-buffer of recent rule changes maintained by the main node.
///
/// Workers send `RuleSyncRequest { current_version }` and receive either an
/// incremental delta (if the worker is caught up enough) or a full snapshot.
pub struct RuleChangelog {
    /// (version_after_change, change) pairs in chronological order
    changes: VecDeque<(u64, RuleChange)>,
    max_retained: usize,
}

impl RuleChangelog {
    pub fn new(max_retained: usize) -> Self {
        Self {
            changes: VecDeque::new(),
            max_retained,
        }
    }

    /// Record a single rule change at the given version
    pub fn push(&mut self, version: u64, change: RuleChange) {
        if self.changes.len() >= self.max_retained {
            self.changes.pop_front();
        }
        self.changes.push_back((version, change));
    }

    /// Return all changes with version > `from_version`, or `None` if the
    /// worker is too far behind and needs a full snapshot instead.
    pub fn delta_since(&self, from_version: u64) -> Option<Vec<RuleChange>> {
        let first = self.changes.front().map(|(v, _)| *v).unwrap_or(0);
        if from_version < first {
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

    /// Build a `RuleSyncResponse` for the given worker version.
    /// Returns an incremental response if possible, otherwise a Full with
    /// an empty snapshot (caller must fill `snapshot_lz4` for Full type).
    pub fn build_response(&self, from_version: u64, current_version: u64) -> RuleSyncResponse {
        match self.delta_since(from_version) {
            Some(changes) => RuleSyncResponse {
                version: current_version,
                sync_type: SyncType::Incremental,
                changes,
                snapshot_lz4: Vec::new(),
            },
            None => RuleSyncResponse {
                version: current_version,
                sync_type: SyncType::Full,
                changes: Vec::new(),
                snapshot_lz4: Vec::new(),
            },
        }
    }
}

/// Compress a raw JSON byte slice using lz4 with prepended original size.
pub fn compress_snapshot(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

/// Decompress an lz4-compressed snapshot produced by [`compress_snapshot`].
pub fn decompress_snapshot(data: &[u8]) -> Result<Vec<u8>> {
    lz4_flex::decompress_size_prepended(data)
        .map_err(|e| anyhow::anyhow!("lz4 decompress failed: {e}"))
}
