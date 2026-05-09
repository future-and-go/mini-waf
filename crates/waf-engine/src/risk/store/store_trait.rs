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

#[cfg(test)]
#[allow(clippy::redundant_clone, clippy::uninlined_format_args)]
mod tests {
    use super::*;
    use crate::risk::state::RiskState;
    use std::net::Ipv4Addr;

    /// Minimal `RiskStore` impl that only implements required methods —
    /// drives default `is_empty` impl through the trait.
    struct NoopStore {
        len: std::sync::atomic::AtomicUsize,
    }

    impl NoopStore {
        const fn new() -> Self {
            Self {
                len: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn set_len(&self, n: usize) {
            self.len.store(n, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl RiskStore for NoopStore {
        async fn read(&self, _key: &RiskKey) -> anyhow::Result<Option<RiskState>> {
            Ok(None)
        }

        async fn apply(&self, _key: &RiskKey, _deltas: &[Contributor], now_ms: i64) -> anyhow::Result<ApplyResult> {
            Ok(ApplyResult {
                state: RiskState::new(now_ms),
                is_new: true,
            })
        }

        async fn force_max(&self, _key: &RiskKey, _until_ms: i64, _now_ms: i64) -> anyhow::Result<()> {
            Ok(())
        }

        async fn purge_expired(&self, _ttl_ms: i64, _now_ms: i64) -> anyhow::Result<usize> {
            Ok(0)
        }

        async fn reset_all(&self) -> anyhow::Result<()> {
            self.set_len(0);
            Ok(())
        }

        async fn len(&self) -> usize {
            self.len.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn default_is_empty_uses_len() {
        let s = NoopStore::new();
        assert!(s.is_empty().await, "len 0 → is_empty true");
        s.set_len(3);
        assert!(!s.is_empty().await, "len > 0 → is_empty false");
        s.reset_all().await.unwrap();
        assert!(s.is_empty().await);
    }

    #[tokio::test]
    async fn trait_methods_callable_through_dyn() {
        let s: Box<dyn RiskStore> = Box::new(NoopStore::new());
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert!(s.read(&key).await.unwrap().is_none());
        let r = s.apply(&key, &[], 100).await.unwrap();
        assert!(r.is_new);
        s.force_max(&key, 1000, 0).await.unwrap();
        assert_eq!(s.purge_expired(0, 0).await.unwrap(), 0);
        assert_eq!(s.len().await, 0);
        assert!(s.is_empty().await);
    }

    #[test]
    fn key_builder_with_each_axis() {
        use crate::risk::key::SessionId;
        let key = RiskKeyBuilder::new()
            .with_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .with_fp_hash(0xDEAD_BEEF)
            .with_session(SessionId::new(b"abc".to_vec()))
            .build();
        assert_eq!(key.axis_count(), 3);
        assert!(key.ip.is_some());
        assert!(key.fp_hash.is_some());
        assert!(key.session.is_some());
    }

    #[test]
    fn key_builder_default_is_empty() {
        let key = RiskKeyBuilder::default().build();
        assert!(key.is_empty());
    }

    #[test]
    fn apply_result_clone_preserves_state() {
        let r = ApplyResult {
            state: RiskState::new(42),
            is_new: true,
        };
        let r2 = r.clone();
        assert_eq!(r2.state.created_ms, 42);
        assert!(r2.is_new);
        let _dbg = format!("{r2:?}");
    }
}
