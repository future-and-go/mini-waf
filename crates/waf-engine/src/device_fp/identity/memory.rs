//! In-memory `IdentityStore` — DashMap-backed sliding-window observer.
//!
//! Each entry tracks distinct IPs/UAs over a configurable window using
//! a deque + count map (O(1) amortized push/evict). Cardinality is capped
//! by `max_entries`; overflow triggers oldest-`last_seen` eviction.
//! TTL sweep is exposed via `purge_expired` and a `spawn_janitor` helper.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use ahash::RandomState;
use async_trait::async_trait;
use dashmap::DashMap;

use crate::device_fp::identity::identity_trait::IdentityStore;
use crate::device_fp::types::{FpKey, IdentityRecord, Observation};

#[derive(Clone, Copy, Debug)]
pub struct MemoryConfig {
    pub ttl_secs: u32,
    pub window_secs: u32,
    pub max_entries: usize,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            ttl_secs: 3600,
            window_secs: 600,
            max_entries: 1_000_000,
        }
    }
}

/// Per-fingerprint sliding-window state.
#[derive(Debug)]
struct Entry {
    first_seen: i64,
    last_seen: i64,
    ip_deque: VecDeque<(IpAddr, i64)>,
    ip_counts: HashMap<IpAddr, u32>,
    ua_deque: VecDeque<(u64, i64)>,
    ua_counts: HashMap<u64, u32>,
}

impl Entry {
    fn new(ip: IpAddr, ua_hash: u64, ts: i64) -> Self {
        let mut e = Self {
            first_seen: ts,
            last_seen: ts,
            ip_deque: VecDeque::new(),
            ip_counts: HashMap::new(),
            ua_deque: VecDeque::new(),
            ua_counts: HashMap::new(),
        };
        e.push(ip, ua_hash, ts);
        e
    }

    fn push(&mut self, ip: IpAddr, ua_hash: u64, ts: i64) {
        self.ip_deque.push_back((ip, ts));
        *self.ip_counts.entry(ip).or_insert(0) += 1;
        self.ua_deque.push_back((ua_hash, ts));
        *self.ua_counts.entry(ua_hash).or_insert(0) += 1;
        if ts > self.last_seen {
            self.last_seen = ts;
        }
        if ts < self.first_seen {
            self.first_seen = ts;
        }
    }

    fn evict_window(&mut self, cutoff: i64) {
        while let Some(&(ip, ts)) = self.ip_deque.front() {
            if ts >= cutoff {
                break;
            }
            self.ip_deque.pop_front();
            if let Some(c) = self.ip_counts.get_mut(&ip) {
                *c -= 1;
                if *c == 0 {
                    self.ip_counts.remove(&ip);
                }
            }
        }
        while let Some(&(ua, ts)) = self.ua_deque.front() {
            if ts >= cutoff {
                break;
            }
            self.ua_deque.pop_front();
            if let Some(c) = self.ua_counts.get_mut(&ua) {
                *c -= 1;
                if *c == 0 {
                    self.ua_counts.remove(&ua);
                }
            }
        }
    }

    fn snapshot(&self, key: FpKey) -> IdentityRecord {
        IdentityRecord {
            key,
            first_seen_unix: self.first_seen,
            last_seen_unix: self.last_seen,
            distinct_ips: clamp_u16(self.ip_counts.len()),
            distinct_uas: clamp_u16(self.ua_counts.len()),
        }
    }
}

fn clamp_u16(n: usize) -> u16 {
    u16::try_from(n).unwrap_or(u16::MAX)
}

#[derive(Debug)]
pub struct MemoryIdentityStore {
    map: DashMap<FpKey, Entry, RandomState>,
    cfg: MemoryConfig,
    hasher_state: RandomState,
}

impl Default for MemoryIdentityStore {
    fn default() -> Self {
        Self::with_config(MemoryConfig::default())
    }
}

impl MemoryIdentityStore {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_config(cfg: MemoryConfig) -> Self {
        let cpus = std::thread::available_parallelism()
            .map_or(8, std::num::NonZeroUsize::get);
        let shards = (cpus * 2).next_power_of_two();
        Self {
            map: DashMap::with_capacity_and_hasher_and_shard_amount(0, RandomState::new(), shards),
            cfg,
            hasher_state: RandomState::new(),
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    #[must_use]
    pub const fn config(&self) -> &MemoryConfig {
        &self.cfg
    }

    fn hash_ua(&self, ua: &str) -> u64 {
        self.hasher_state.hash_one(ua)
    }

    /// Best-effort eviction of the entry with the smallest `last_seen`
    /// while size exceeds `max_entries`. O(N) per pass — runs only on
    /// overflow, which the cap is meant to make rare.
    fn enforce_cap(&self) {
        while self.map.len() > self.cfg.max_entries {
            let victim = self
                .map
                .iter()
                .min_by_key(|r| r.value().last_seen)
                .map(|r| r.key().clone());
            match victim {
                Some(k) => {
                    self.map.remove(&k);
                }
                None => break,
            }
        }
    }
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn observe(
        &self,
        key: &FpKey,
        ip: IpAddr,
        ua: &str,
        ts: i64,
    ) -> anyhow::Result<Observation> {
        let ua_hash = self.hash_ua(ua);
        let cutoff = ts.saturating_sub(i64::from(self.cfg.window_secs));

        let obs = {
            use dashmap::mapref::entry::Entry as DEntry;
            let mut entry_ref = match self.map.entry(key.clone()) {
                DEntry::Occupied(o) => {
                    let mut r = o.into_ref();
                    r.value_mut().push(ip, ua_hash, ts);
                    r
                }
                DEntry::Vacant(v) => v.insert(Entry::new(ip, ua_hash, ts)),
            };
            let e = entry_ref.value_mut();
            e.evict_window(cutoff);
            let snap = Observation {
                distinct_ips_in_window: clamp_u16(e.ip_counts.len()),
                distinct_uas_in_window: clamp_u16(e.ua_counts.len()),
                first_seen_unix: e.first_seen,
                last_seen_unix: e.last_seen,
            };
            drop(entry_ref);
            snap
        };

        if self.map.len() > self.cfg.max_entries {
            self.enforce_cap();
        }
        Ok(obs)
    }

    async fn lookup(&self, key: &FpKey) -> anyhow::Result<Option<IdentityRecord>> {
        Ok(self.map.get(key).map(|r| r.value().snapshot(key.clone())))
    }

    async fn purge_expired(&self) -> anyhow::Result<usize> {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now.saturating_sub(i64::from(self.cfg.ttl_secs));
        let mut purged = 0_usize;
        self.map.retain(|_, e| {
            if e.last_seen < cutoff {
                purged += 1;
                false
            } else {
                true
            }
        });
        Ok(purged)
    }
}

/// Spawn a background TTL janitor that calls `purge_expired` every
/// `ttl_secs / 4` seconds (min 1s). Returned handle aborts the loop on drop.
#[must_use]
pub fn spawn_janitor(store: Arc<MemoryIdentityStore>) -> tokio::task::JoinHandle<()> {
    let interval_secs = u64::from(store.cfg.ttl_secs / 4).max(1);
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(interval_secs));
        tick.tick().await; // first tick fires immediately — skip it
        loop {
            tick.tick().await;
            if let Err(err) = store.purge_expired().await {
                tracing::warn!(?err, "device_fp memory janitor purge failed");
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::identity::conformance::run_store_conformance;
    use std::net::Ipv4Addr;

    fn k(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(crate::device_fp::types::FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    #[tokio::test]
    async fn conformance_suite() {
        let store: Arc<dyn IdentityStore> = Arc::new(MemoryIdentityStore::with_config(MemoryConfig {
            ttl_secs: 3600,
            window_secs: 600,
            max_entries: 8,
        }));
        run_store_conformance(store).await;
    }

    #[tokio::test]
    async fn observe_returns_first_seen_ts() {
        let store = MemoryIdentityStore::new();
        let obs = store
            .observe(&k("a"), IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", 42)
            .await
            .unwrap();
        assert_eq!(obs.first_seen_unix, 42);
        assert_eq!(obs.distinct_ips_in_window, 1);
    }

    #[tokio::test]
    async fn janitor_runs_without_panic() {
        let store = Arc::new(MemoryIdentityStore::with_config(MemoryConfig {
            ttl_secs: 4,
            window_secs: 2,
            max_entries: 16,
        }));
        let handle = spawn_janitor(Arc::clone(&store));
        tokio::time::sleep(Duration::from_millis(50)).await;
        handle.abort();
    }
}
