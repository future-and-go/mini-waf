//! FR-025 in-memory risk store with triple-index pattern.
//!
//! Three `DashMap` indices keyed independently (IP, `fp_hash`, session) share
//! `Arc<RwLock<RiskState>>`. On collision (different Arcs for same actor),
//! merge by taking max-score and unifying the Arc.

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;
use parking_lot::RwLock;
use tokio::time::interval;
use tracing::{debug, info};

use crate::risk::key::RiskKey;
use crate::risk::score::fold;
use crate::risk::state::{Contributor, RiskState};
use crate::risk::store::store_trait::{ApplyResult, RiskStore};

type StateRef = Arc<RwLock<RiskState>>;

/// In-memory risk store with triple-index pattern.
#[allow(clippy::struct_field_names)]
pub struct MemoryRiskStore {
    by_ip: DashMap<IpAddr, StateRef>,
    by_fp: DashMap<u64, StateRef>,
    by_session: DashMap<Vec<u8>, StateRef>,
}

impl MemoryRiskStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_ip: DashMap::new(),
            by_fp: DashMap::new(),
            by_session: DashMap::new(),
        }
    }

    /// Spawn a background task that periodically purges expired entries.
    pub fn start_purge_loop(self: &Arc<Self>, ttl_ms: i64, interval_secs: u64) {
        let store = Arc::clone(self);
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(interval_secs));
            loop {
                tick.tick().await;
                let now_ms = chrono::Utc::now().timestamp_millis();
                match store.purge_expired(ttl_ms, now_ms).await {
                    Ok(n) if n > 0 => debug!(purged = n, "risk store: purged expired entries"),
                    Ok(_) => {}
                    Err(e) => tracing::warn!(error = %e, "risk store: purge failed"),
                }
            }
        });
    }

    /// Find existing state across all indices, returning the max-score one.
    fn find_existing(&self, key: &RiskKey) -> Option<StateRef> {
        let mut candidates: Vec<StateRef> = Vec::with_capacity(3);

        if let Some(ip) = key.ip
            && let Some(entry) = self.by_ip.get(&ip)
        {
            candidates.push(Arc::clone(entry.value()));
        }
        if let Some(fp) = key.fp_hash
            && let Some(entry) = self.by_fp.get(&fp)
        {
            candidates.push(Arc::clone(entry.value()));
        }
        if let Some(ref sess) = key.session
            && let Some(entry) = self.by_session.get(sess.as_bytes())
        {
            candidates.push(Arc::clone(entry.value()));
        }

        if candidates.is_empty() {
            return None;
        }

        // Take the max-score state (merge-on-collide: defensive, assume worst)
        candidates.into_iter().max_by_key(|s| s.read().clamped_score)
    }

    /// Insert or update the state ref into all applicable indices.
    fn upsert_indices(&self, key: &RiskKey, state_ref: &StateRef) {
        if let Some(ip) = key.ip {
            self.by_ip.insert(ip, Arc::clone(state_ref));
        }
        if let Some(fp) = key.fp_hash {
            self.by_fp.insert(fp, Arc::clone(state_ref));
        }
        if let Some(ref sess) = key.session {
            self.by_session.insert(sess.as_bytes().to_vec(), Arc::clone(state_ref));
        }
    }

    /// Count unique states (not index entries, which may have duplicates).
    fn unique_state_count(&self) -> usize {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        for entry in &self.by_ip {
            seen.insert(Arc::as_ptr(entry.value()) as usize);
        }
        for entry in &self.by_fp {
            seen.insert(Arc::as_ptr(entry.value()) as usize);
        }
        for entry in &self.by_session {
            seen.insert(Arc::as_ptr(entry.value()) as usize);
        }
        seen.len()
    }
}

impl Default for MemoryRiskStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RiskStore for MemoryRiskStore {
    async fn read(&self, key: &RiskKey) -> anyhow::Result<Option<RiskState>> {
        Ok(self.find_existing(key).map(|s| s.read().clone()))
    }

    #[allow(clippy::option_if_let_else)]
    async fn apply(&self, key: &RiskKey, deltas: &[Contributor], now_ms: i64) -> anyhow::Result<ApplyResult> {
        if key.is_empty() {
            return Ok(ApplyResult {
                state: RiskState::new(now_ms),
                is_new: true,
            });
        }

        let (state_ref, is_new) = if let Some(existing) = self.find_existing(key) {
            (existing, false)
        } else {
            let new_state = RiskState::new(now_ms);
            let new_ref = Arc::new(RwLock::new(new_state));
            self.upsert_indices(key, &new_ref);
            (new_ref, true)
        };

        // Apply deltas under write lock
        {
            let mut state = state_ref.write();
            fold(&mut state, deltas, now_ms);
        }

        // Re-unify indices (merge-on-collide: ensure all axes point to same Arc)
        if !is_new {
            self.upsert_indices(key, &state_ref);
        }

        let state = state_ref.read().clone();
        Ok(ApplyResult { state, is_new })
    }

    #[allow(clippy::option_if_let_else)]
    async fn force_max(&self, key: &RiskKey, until_ms: i64, now_ms: i64) -> anyhow::Result<()> {
        if key.is_empty() {
            return Ok(());
        }

        let state_ref = if let Some(existing) = self.find_existing(key) {
            existing
        } else {
            let new_state = RiskState::new(now_ms);
            let new_ref = Arc::new(RwLock::new(new_state));
            self.upsert_indices(key, &new_ref);
            new_ref
        };

        {
            let mut state = state_ref.write();
            state.raw_score = 100;
            state.clamped_score = 100;
            state.pinned_until_ms = Some(until_ms);
            state.last_updated_ms = now_ms;
        }

        self.upsert_indices(key, &state_ref);
        Ok(())
    }

    async fn purge_expired(&self, ttl_ms: i64, now_ms: i64) -> anyhow::Result<usize> {
        const MAX_PER_TICK: usize = 1000;
        let mut purged = 0;

        // Collect expired IP keys
        let stale_ip_keys: Vec<IpAddr> = self
            .by_ip
            .iter()
            .filter(|e| e.value().read().idle_ms(now_ms) > ttl_ms)
            .map(|e| *e.key())
            .take(MAX_PER_TICK)
            .collect();

        for ip in stale_ip_keys {
            self.by_ip.remove(&ip);
            purged += 1;
        }

        // Collect expired fingerprint keys
        let stale_fingerprint_keys: Vec<u64> = self
            .by_fp
            .iter()
            .filter(|e| e.value().read().idle_ms(now_ms) > ttl_ms)
            .map(|e| *e.key())
            .take(MAX_PER_TICK.saturating_sub(purged))
            .collect();

        for fp in stale_fingerprint_keys {
            self.by_fp.remove(&fp);
            purged += 1;
        }

        // Collect expired session keys
        let stale_session_keys: Vec<Vec<u8>> = self
            .by_session
            .iter()
            .filter(|e| e.value().read().idle_ms(now_ms) > ttl_ms)
            .map(|e| e.key().clone())
            .take(MAX_PER_TICK.saturating_sub(purged))
            .collect();

        for sess in stale_session_keys {
            self.by_session.remove(&sess);
            purged += 1;
        }

        Ok(purged)
    }

    async fn reset_all(&self) -> anyhow::Result<()> {
        // Clear all indices atomically
        self.by_ip.clear();
        self.by_fp.clear();
        self.by_session.clear();

        info!("risk store: reset_all completed");
        Ok(())
    }

    async fn len(&self) -> usize {
        self.unique_state_count()
    }
}

#[cfg(test)]
#[allow(clippy::similar_names)]
mod tests {
    use super::*;
    use crate::risk::key::SessionId;
    use crate::risk::state::ContributorKind;
    use std::net::Ipv4Addr;

    fn make_contributor(delta: i16) -> Contributor {
        Contributor::new(ContributorKind::Seed, delta, 1000)
    }

    #[tokio::test]
    async fn apply_creates_new_state() {
        let store = MemoryRiskStore::new();
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        let deltas = vec![make_contributor(25)];

        let result = store.apply(&key, &deltas, 1000).await.unwrap();
        assert!(result.is_new);
        assert_eq!(result.state.clamped_score, 25);
    }

    #[tokio::test]
    async fn apply_updates_existing_state() {
        let store = MemoryRiskStore::new();
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        store.apply(&key, &[make_contributor(20)], 1000).await.unwrap();
        let result = store.apply(&key, &[make_contributor(15)], 2000).await.unwrap();

        assert!(!result.is_new);
        assert_eq!(result.state.clamped_score, 35);
    }

    #[tokio::test]
    async fn read_returns_max_across_indices() {
        let store = MemoryRiskStore::new();

        // Insert via IP with score 30
        let ip_only_key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        store.apply(&ip_only_key, &[make_contributor(30)], 1000).await.unwrap();

        // Insert via fp_hash with score 50
        let fingerprint_key = RiskKey {
            ip: None,
            fp_hash: Some(12345),
            session: None,
        };
        store
            .apply(&fingerprint_key, &[make_contributor(50)], 1000)
            .await
            .unwrap();

        // Read with both axes — should get max (50)
        let combined_key = RiskKey {
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            fp_hash: Some(12345),
            session: None,
        };
        let state = store.read(&combined_key).await.unwrap().unwrap();
        assert_eq!(state.clamped_score, 50);
    }

    #[tokio::test]
    async fn force_max_sets_score_to_100() {
        let store = MemoryRiskStore::new();
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        store.apply(&key, &[make_contributor(25)], 1000).await.unwrap();
        store.force_max(&key, 5000, 2000).await.unwrap();

        let state = store.read(&key).await.unwrap().unwrap();
        assert_eq!(state.clamped_score, 100);
        assert_eq!(state.pinned_until_ms, Some(5000));
    }

    #[tokio::test]
    async fn reset_all_clears_store() {
        let store = MemoryRiskStore::new();
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        store.apply(&key, &[make_contributor(25)], 1000).await.unwrap();
        assert!(!store.is_empty().await);

        store.reset_all().await.unwrap();
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn purge_removes_expired_entries() {
        let store = MemoryRiskStore::new();
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));

        store.apply(&key, &[make_contributor(25)], 1000).await.unwrap();

        // Entry was updated at 1000, now is 5000, TTL is 2000 → should expire
        let purged = store.purge_expired(2000, 5000).await.unwrap();
        assert_eq!(purged, 1);
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn triple_index_unifies_state() {
        let store = MemoryRiskStore::new();

        // Apply with all three axes
        let full_key = RiskKey {
            ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            fp_hash: Some(99999),
            session: Some(SessionId::new(vec![1, 2, 3, 4])),
        };
        store.apply(&full_key, &[make_contributor(40)], 1000).await.unwrap();

        // Read via IP only
        let ip_only_key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let state = store.read(&ip_only_key).await.unwrap().unwrap();
        assert_eq!(state.clamped_score, 40);

        // Read via fp_hash only
        let fingerprint_key = RiskKey {
            ip: None,
            fp_hash: Some(99999),
            session: None,
        };
        let state = store.read(&fingerprint_key).await.unwrap().unwrap();
        assert_eq!(state.clamped_score, 40);

        // Read via session only
        let session_key = RiskKey {
            ip: None,
            fp_hash: None,
            session: Some(SessionId::new(vec![1, 2, 3, 4])),
        };
        let state = store.read(&session_key).await.unwrap().unwrap();
        assert_eq!(state.clamped_score, 40);
    }
}
