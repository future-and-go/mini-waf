//! FR-011 Phase 1 — lock-free per-actor `Recorder`.
//!
//! `DashMap` keyed by `FpKey` (reused from `device_fp::types`, DRY). Writes
//! upsert in O(1) via the entry API. Reads use `snapshot()` — clones the
//! small bounded state out so classifiers never hold a shard guard while
//! evaluating (deadlock-safe).
//!
//! Time is monotonic ms since `anchor: Instant`; wall-clock jumps cannot
//! produce negative intervals. Path hashing reuses `ahash::RandomState`
//! (already a workspace dep — see `identity::memory::MemoryIdentityStore`)
//! instead of pulling in `xxhash-rust`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use ahash::RandomState;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use tokio::task::JoinHandle;
use waf_common::tier::Tier;

use crate::device_fp::behavior::config::BehaviorConfig;
use crate::device_fp::behavior::path_classifier;
use crate::device_fp::behavior::state::{ActorBehavior, Sample};
use crate::device_fp::types::FpKey;

/// Bounded snapshot of an actor's state — handed to classifiers so they
/// can evaluate without holding the underlying `DashMap` shard guard.
#[derive(Clone, Debug)]
pub struct ActorBehaviorSnapshot {
    /// Oldest → newest. Bounded by `WINDOW` (16) — small one-shot alloc.
    pub samples: Vec<Sample>,
    pub distinct_paths_len: usize,
    pub updated_ms: u64,
}

pub struct Recorder {
    actors: DashMap<FpKey, ActorBehavior, RandomState>,
    anchor: Instant,
    path_hasher: RandomState,
    cfg: Arc<ArcSwap<BehaviorConfig>>,
}

impl Recorder {
    #[must_use]
    pub fn new(cfg: Arc<ArcSwap<BehaviorConfig>>) -> Self {
        let cpus = std::thread::available_parallelism().map_or(8, std::num::NonZeroUsize::get);
        let shards = (cpus * 2).next_power_of_two();
        Self {
            actors: DashMap::with_capacity_and_hasher_and_shard_amount(0, RandomState::new(), shards),
            anchor: Instant::now(),
            path_hasher: RandomState::new(),
            cfg,
        }
    }

    /// Saturating-cast monotonic ms since `anchor`. `u128 → u64` saturates
    /// at `u64::MAX` (≈585 million years) — defensive only.
    fn now_ms(&self) -> u64 {
        u64::try_from(self.anchor.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Insert a new behavioral sample for `key`. Hot path: <1 µs target,
    /// zero allocations after the actor's first observation.
    ///
    /// Path-exemption flags are computed here (not at the call site) so
    /// providers reading the snapshot don't need the original path string —
    /// only the small flag bits travel into the ring.
    pub fn record(&self, key: &FpKey, path: &str, had_referer: bool, had_prefetch_hint: bool, tier: Tier) {
        let cfg = self.cfg.load();
        let sample = Sample {
            ts_ms: self.now_ms(),
            path_hash: self.path_hasher.hash_one(path),
            had_referer,
            had_prefetch_hint,
            is_entry_path: path_classifier::is_entry_path(path, &cfg.zero_depth.exempt_entry_paths),
            is_low_signal_path: path_classifier::is_low_signal_path(
                path,
                &cfg.missing_referer.exempt_paths,
                &cfg.missing_referer.exempt_prefixes,
            ),
            tier,
        };
        self.actors
            .entry(key.clone())
            .or_insert_with(ActorBehavior::new)
            .record(sample);
    }

    /// Clone the bounded actor state. Returns `None` if the actor is unseen.
    pub fn snapshot(&self, key: &FpKey) -> Option<ActorBehaviorSnapshot> {
        self.actors.get(key).map(|r| {
            let v = r.value();
            ActorBehaviorSnapshot {
                samples: v.samples().collect(),
                distinct_paths_len: v.distinct_paths_len(),
                updated_ms: v.updated_ms,
            }
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.actors.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }

    /// Drop actors idle longer than `actor_ttl_secs`. Returns count purged.
    pub fn purge_expired(&self) -> usize {
        let ttl_ms = u64::from(self.cfg.load().actor_ttl_secs).saturating_mul(1000);
        let cutoff = self.now_ms().saturating_sub(ttl_ms);
        let mut purged = 0_usize;
        self.actors.retain(|_, v| {
            if v.updated_ms < cutoff {
                purged += 1;
                false
            } else {
                true
            }
        });
        purged
    }

    /// Spawn a background TTL janitor. Handle aborts the loop on drop.
    /// Mirrors `device_fp::identity::memory::spawn_janitor` (DRY pattern).
    #[must_use]
    pub fn spawn_janitor(self: Arc<Self>, period: Duration) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(period);
            tick.tick().await; // first tick fires immediately
            loop {
                tick.tick().await;
                self.purge_expired();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::types::FingerprintValue;

    fn cfg(ttl_secs: u32) -> Arc<ArcSwap<BehaviorConfig>> {
        Arc::new(ArcSwap::from_pointee(BehaviorConfig {
            window_size: 16,
            actor_ttl_secs: ttl_secs,
            ..BehaviorConfig::default()
        }))
    }

    fn key(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    #[test]
    fn record_upserts_new_key() {
        let r = Recorder::new(cfg(600));
        let k = key("a");
        assert!(r.snapshot(&k).is_none());
        r.record(&k, "/x", false, false, Tier::CatchAll);
        let snap = r.snapshot(&k).expect("snapshot present after record");
        assert_eq!(snap.samples.len(), 1);
        assert_eq!(snap.distinct_paths_len, 1);
    }

    #[test]
    fn snapshot_clones_bounded_state() {
        let r = Recorder::new(cfg(600));
        let k = key("b");
        for i in 0..20 {
            r.record(&k, &format!("/p/{i}"), false, false, Tier::CatchAll);
        }
        let snap = r.snapshot(&k).expect("snapshot present");
        // Ring caps at 16 — oldest 4 dropped.
        assert_eq!(snap.samples.len(), 16);
        // Distinct paths cap at 8.
        assert_eq!(snap.distinct_paths_len, 8);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_inserts_no_panic() {
        let r = Arc::new(Recorder::new(cfg(600)));
        let mut handles = Vec::new();
        for task_id in 0..100u32 {
            let r = Arc::clone(&r);
            handles.push(tokio::spawn(async move {
                for i in 0..100u32 {
                    let k = key(&format!("t{task_id}-k{}", i % 10));
                    r.record(&k, "/x", false, false, Tier::CatchAll);
                }
            }));
        }
        for h in handles {
            h.await.expect("task should not panic");
        }
        // 100 tasks × 10 distinct keys each = up to 1000 unique actors.
        assert!(!r.is_empty());
        assert!(r.len() <= 1000);
    }

    #[test]
    fn purge_expired_removes_idle_actors() {
        // ttl=0 → every entry is "expired" immediately on the next tick of
        // the monotonic clock. Sleep 2 ms to ensure now_ms advances past
        // the recorded sample's ts_ms.
        let r = Recorder::new(cfg(0));
        let k = key("c");
        r.record(&k, "/x", false, false, Tier::CatchAll);
        std::thread::sleep(Duration::from_millis(2));
        let purged = r.purge_expired();
        assert_eq!(purged, 1);
        assert!(r.snapshot(&k).is_none());
    }

    #[test]
    fn purge_keeps_fresh_actors() {
        let r = Recorder::new(cfg(3600));
        let k = key("d");
        r.record(&k, "/x", false, false, Tier::CatchAll);
        let purged = r.purge_expired();
        assert_eq!(purged, 0);
        assert!(r.snapshot(&k).is_some());
    }

    #[tokio::test]
    async fn janitor_runs_without_panic() {
        let r = Arc::new(Recorder::new(cfg(3600)));
        let h = Arc::clone(&r).spawn_janitor(Duration::from_millis(10));
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.abort();
    }
}
