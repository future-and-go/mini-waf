//! In-memory snapshot of threat-intelligence feed load state.
//!
//! Populated by the relay module after `feeds.load()` completes; consumed by
//! the admin API endpoint `GET /api/reputation/status` so the panel can show
//! "feeds loaded at startup" or a real count.
//!
//! The skeleton is intentionally empty in this PR — the relay wiring and
//! admin API land in follow-up PRs and bring it to life.
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;

/// Immutable point-in-time view of the registry.
#[derive(Debug, Clone, Default)]
pub struct FeedStatusSnapshot {
    pub available: bool,
    pub tor_count: Option<usize>,
    pub asn_count: Option<usize>,
    pub last_refreshed: Option<DateTime<Utc>>,
}

/// Thread-safe registry. Cheap to clone (`Arc` internally).
#[derive(Debug, Default, Clone)]
pub struct FeedStatusRegistry {
    inner: Arc<RwLock<FeedStatusSnapshot>>,
}

impl FeedStatusRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Read-side: point-in-time snapshot for HTTP handlers.
    pub fn snapshot(&self) -> FeedStatusSnapshot {
        self.inner.read().clone()
    }

    /// Mark the feeds as loaded with the given counts (write-side, phase 02).
    pub fn mark_loaded(&self, tor_count: usize, asn_count: usize) {
        let mut guard = self.inner.write();
        guard.available = true;
        guard.tor_count = Some(tor_count);
        guard.asn_count = Some(asn_count);
        guard.last_refreshed = Some(Utc::now());
    }

    /// Mark feeds as unavailable (e.g., load failure).
    pub fn mark_unavailable(&self) {
        let mut guard = self.inner.write();
        guard.available = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_snapshot_is_unavailable() {
        let snap = FeedStatusSnapshot::default();
        assert!(!snap.available);
        assert!(snap.tor_count.is_none());
        assert!(snap.asn_count.is_none());
        assert!(snap.last_refreshed.is_none());
    }

    #[test]
    fn new_registry_returns_unavailable_snapshot() {
        let reg = FeedStatusRegistry::new();
        let snap = reg.snapshot();
        assert!(!snap.available);
    }

    #[test]
    fn mark_loaded_populates_snapshot() {
        let reg = FeedStatusRegistry::new();
        reg.mark_loaded(1500, 75_000);
        let snap = reg.snapshot();
        assert!(snap.available);
        assert_eq!(snap.tor_count, Some(1500));
        assert_eq!(snap.asn_count, Some(75_000));
        assert!(snap.last_refreshed.is_some());
    }

    #[test]
    fn mark_unavailable_flips_available_flag() {
        let reg = FeedStatusRegistry::new();
        reg.mark_loaded(100, 200);
        assert!(reg.snapshot().available);
        reg.mark_unavailable();
        assert!(!reg.snapshot().available);
    }

    #[test]
    fn registry_clone_shares_inner_state() {
        let reg1 = FeedStatusRegistry::new();
        let reg2 = reg1.clone();
        reg1.mark_loaded(10, 20);
        let snap = reg2.snapshot();
        assert!(snap.available);
        assert_eq!(snap.tor_count, Some(10));
    }
}
