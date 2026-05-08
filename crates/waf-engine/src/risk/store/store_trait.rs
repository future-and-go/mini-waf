//! FR-025 risk store trait.
//!
//! Defines the async interface for risk state persistence. Implementations
//! must be `Send + Sync` for use in the async pipeline.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::risk::key::{RiskKey, SessionId};
use crate::risk::state::{Contributor, RiskState};

/// Result of an `apply` operation — the post-update state.
#[derive(Clone, Debug)]
pub struct ApplyResult {
    pub state: RiskState,
    /// True if this was a new entry (not an update to existing).
    pub is_new: bool,
}

/// Async trait for risk state storage.
///
/// Implementations must handle the triple-index pattern: a single actor may
/// be keyed by IP, fingerprint hash, and/or session. All three indices must
/// resolve to the SAME underlying state for a given actor.
///
/// # Merge-on-Collide Rule
///
/// When `apply` discovers that different indices point to different `RiskState`
/// instances (e.g., a session was created before fingerprinting was enabled),
/// the implementation MUST merge by taking the max-score state and unifying
/// the Arc across all indices. This ensures risk cannot be shed by changing
/// identity axes.
#[async_trait]
pub trait RiskStore: Send + Sync {
    /// Read the current risk state for the given key.
    ///
    /// If multiple axes are present in `key`, returns the MAX score across
    /// all found states (defensive: assume worst-case).
    async fn read(&self, key: &RiskKey) -> anyhow::Result<Option<RiskState>>;

    /// Apply deltas to the state for `key`, creating it if absent.
    ///
    /// Returns the post-update state in a single round-trip (no follow-up read).
    /// If `deltas` is empty, still updates timestamps (touch operation).
    async fn apply(&self, key: &RiskKey, deltas: &[Contributor], now_ms: i64) -> anyhow::Result<ApplyResult>;

    /// Force the state to max score (100) until `until_ms`.
    ///
    /// Used for honeypot traps (FR-028). Sets `pinned_until_ms` and floors
    /// the score at 100 regardless of decay.
    async fn force_max(&self, key: &RiskKey, until_ms: i64, now_ms: i64) -> anyhow::Result<()>;

    /// Purge entries that have been idle longer than `ttl_ms`.
    ///
    /// Returns the number of entries purged.
    async fn purge_expired(&self, ttl_ms: i64, now_ms: i64) -> anyhow::Result<usize>;

    /// Atomically reset all state.
    ///
    /// Used for emergency "amnesty" or testing. Implementation MUST swap-with-empty
    /// (not iterate-and-clear) to ensure concurrent readers see either pre or post
    /// state, never partial.
    async fn reset_all(&self) -> anyhow::Result<()>;

    /// Get the current number of tracked actors.
    async fn len(&self) -> usize;

    /// Check if the store is empty.
    async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

/// Builder for `RiskKey` from request context.
pub struct RiskKeyBuilder {
    key: RiskKey,
}

impl RiskKeyBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            key: RiskKey::default(),
        }
    }

    #[must_use]
    pub const fn with_ip(mut self, ip: IpAddr) -> Self {
        self.key.ip = Some(ip);
        self
    }

    #[must_use]
    pub const fn with_fp_hash(mut self, hash: u64) -> Self {
        self.key.fp_hash = Some(hash);
        self
    }

    #[must_use]
    pub fn with_session(mut self, session: SessionId) -> Self {
        self.key.session = Some(session);
        self
    }

    #[must_use]
    pub fn build(self) -> RiskKey {
        self.key
    }
}

impl Default for RiskKeyBuilder {
    fn default() -> Self {
        Self::new()
    }
}
