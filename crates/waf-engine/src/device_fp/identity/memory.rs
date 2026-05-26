//! In-memory `IdentityStore` — DashMap-backed sliding-window observer.
//!
//! Each entry tracks distinct IPs/UAs over a configurable window using
//! a deque + count map (O(1) amortized push/evict). Cardinality is capped
//! by `max_entries`; overflow triggers oldest-`last_seen` eviction.
//! TTL sweep is exposed via `purge_expired` and a `spawn_janitor` helper.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use ahash::RandomState;
use async_trait::async_trait;
use dashmap::DashMap;

use crate::device_fp::identity::identity_trait::IdentityStore;
use crate::device_fp::types::{FpKey, IdentityRecord, Observation};

/// How many `observe` calls past `max_entries` must happen before an
/// eviction sweep runs. Amortizes the O(N) full-map scan so that an
/// attacker rotating JA3 / UA values one-per-request cannot turn cap
/// enforcement itself into a CPU-`DoS` primitive. Mirrors the
/// `scanner_state::EVICT_INTERVAL` pattern.
const EVICT_INTERVAL: usize = 1024;

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
    /// Counts `observe` calls that find the map already over `max_entries`.
    /// Only every `EVICT_INTERVAL`-th such call pays the eviction scan, so
    /// the per-request cost amortizes to O(N / `EVICT_INTERVAL`).
    evict_ticker: AtomicUsize,
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
        let cpus = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
        let shards = (cpus * 2).next_power_of_two();
        Self {
            map: DashMap::with_capacity_and_hasher_and_shard_amount(0, RandomState::new(), shards),
            cfg,
            hasher_state: RandomState::new(),
            evict_ticker: AtomicUsize::new(0),
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

    /// Drop the oldest entries (by `last_seen`) — but only once every
    /// [`EVICT_INTERVAL`] over-cap calls. Each sweep is a single
    /// partial-sort pass (O(N) average via `select_nth_unstable_by_key`)
    /// rather than the previous `while len > max { iter().min_by_key() }`
    /// loop which was O(N²) per pass under sustained overflow.
    ///
    /// Drops at least the current overflow but no fewer than 10 % of the
    /// map so a single sweep buys a meaningful runway before the next
    /// one is needed; otherwise an attacker rotating JA3 values could
    /// keep us at `max_entries + 1` and pay the O(N) cost every
    /// `EVICT_INTERVAL` requests.
    fn enforce_cap(&self) {
        if self.map.len() <= self.cfg.max_entries {
            return;
        }
        let tick = self.evict_ticker.fetch_add(1, Ordering::Relaxed);
        if !tick.is_multiple_of(EVICT_INTERVAL) {
            return;
        }
        let mut ages: Vec<(FpKey, i64)> = self
            .map
            .iter()
            .map(|kv| (kv.key().clone(), kv.value().last_seen))
            .collect();
        let over = self.map.len().saturating_sub(self.cfg.max_entries);
        let drop_n = over.max(ages.len() / 10).min(ages.len());
        if drop_n == 0 {
            return;
        }
        if drop_n < ages.len() {
            // O(N) average — partial sort, not a full O(N log N) sort.
            ages.select_nth_unstable_by_key(drop_n - 1, |(_, t)| *t);
        }
        for (k, _) in ages.into_iter().take(drop_n) {
            self.map.remove(&k);
        }
    }
}

#[async_trait]
impl IdentityStore for MemoryIdentityStore {
    async fn observe(&self, key: &FpKey, ip: IpAddr, ua: &str, ts: i64) -> anyhow::Result<Observation> {
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

        self.enforce_cap();
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

    // ── Amortized cap eviction (#86) ─────────────────────────────────────────
    //
    // Old `enforce_cap` ran a full O(N) `min_by_key` scan after every observe
    // once size exceeded `max_entries`. An attacker rotating JA3 / UA values
    // one-per-request kept the map at `max+1` so every request paid the
    // O(N) tax → CPU amplification under sustained traffic.
    //
    // New behaviour mirrors `scanner_state::evict_if_over_cap`: an
    // `AtomicUsize` ticker counts over-cap observes; only every
    // `EVICT_INTERVAL`-th call pays the eviction scan, and that scan uses
    // `select_nth_unstable_by_key` to drop at least 10 % of entries in a
    // single O(N)-average pass — buying a runway so the next sweep is far
    // off rather than the immediate-next request.

    #[tokio::test]
    async fn enforce_cap_skips_eviction_when_under_cap() {
        let store = MemoryIdentityStore::with_config(MemoryConfig {
            ttl_secs: 3600,
            window_secs: 600,
            max_entries: 1000,
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        for i in 0..500_i64 {
            store.observe(&k(&format!("fp-{i}")), ip, "ua", i).await.unwrap();
        }
        assert_eq!(store.len(), 500, "no eviction while under cap");
    }

    #[tokio::test]
    async fn enforce_cap_drops_oldest_after_eviction_interval() {
        let max = 50;
        let store = MemoryIdentityStore::with_config(MemoryConfig {
            ttl_secs: 3600,
            window_secs: 600,
            max_entries: max,
        });
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);

        // Burst enough unique fingerprints past the cap to guarantee at least
        // one eviction tick fires. Each observe carries a monotonically
        // increasing `ts` so the oldest entries are the smallest-numbered ones.
        let total = max + EVICT_INTERVAL + 100;
        for i in 0..total {
            let ts = i64::try_from(i).unwrap_or(i64::MAX);
            store.observe(&k(&format!("fp-{i}")), ip, "ua", ts).await.unwrap();
        }

        // Cap drift is bounded by `EVICT_INTERVAL` — the ticker fires once
        // per `EVICT_INTERVAL` over-cap calls, so by the time we add another
        // `EVICT_INTERVAL` entries the next sweep has already run.
        assert!(
            store.len() <= max + EVICT_INTERVAL,
            "len {} must stay bounded by max + EVICT_INTERVAL ({})",
            store.len(),
            max + EVICT_INTERVAL,
        );
        // The very first inserted fingerprint must be among the evicted —
        // proves the partial-sort actually targets the oldest `last_seen`,
        // not arbitrary entries.
        assert!(
            store.lookup(&k("fp-0")).await.unwrap().is_none(),
            "oldest fingerprint must be evicted",
        );
    }
}
