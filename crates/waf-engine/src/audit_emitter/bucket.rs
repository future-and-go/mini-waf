//! Per-`(client_ip, rule_id)` rate-limit bucket store.
//!
//! Mirrors `checks::ddos::store::memory` — `DashMap<Arc<str>, ExpiresMs>` for
//! shared concurrent access without per-call `String` allocation. The
//! emitter's hot path calls `claim()` only AFTER a successful `try_send`
//! (red-team F1.3 fix) so a full channel never poisons the bucket and
//! blacks out future hits.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

/// Wall-clock epoch milliseconds. Returns `0` on platforms with broken clocks
/// (mirrors the `DDoS` store's policy of staying inert rather than panicking).
#[must_use]
pub fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Bucket key in the form `"<client_ip>#<rule_id>"`.
///
/// `Arc<str>` keeps the key copy-cheap for `DashMap` shards while avoiding
/// per-hit `String` allocation when callers thread through the same key.
#[must_use]
pub fn make_key(client_ip: &str, rule_id: &str) -> Arc<str> {
    let mut s = String::with_capacity(client_ip.len() + 1 + rule_id.len());
    s.push_str(client_ip);
    s.push('#');
    s.push_str(rule_id);
    Arc::from(s.into_boxed_str())
}

/// Thin wrapper around `DashMap` exposing only the operations the emitter
/// needs (check / claim / GC / len). Tests live on this surface so they
/// don't have to spin up the full emitter.
#[derive(Debug, Default, Clone)]
pub struct BucketStore {
    map: Arc<DashMap<Arc<str>, i64>>,
}

impl BucketStore {
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
    }

    /// Returns `true` when the key currently sits inside an unexpired window.
    #[must_use]
    pub fn is_active(&self, key: &Arc<str>, now_ms: i64) -> bool {
        self.map.get(key).is_some_and(|e| *e.value() > now_ms)
    }

    /// Insert / refresh an active bucket. Caller is responsible for invoking
    /// this only AFTER the corresponding DB insert was enqueued.
    pub fn claim(&self, key: Arc<str>, expires_ms: i64) {
        self.map.insert(key, expires_ms);
    }

    /// Atomic check-and-claim. Returns `true` when the bucket was free
    /// (and now reserved with `expires_ms`); returns `false` when the
    /// bucket was already active for this key — caller must treat as
    /// rate-limited.
    ///
    /// Race fix for issue #60 C2: two concurrent emits with the same
    /// `(client_ip, rule_id)` previously both passed an `is_active` check
    /// then both called `claim`, producing duplicate rows. This method
    /// performs the check + write under one `DashMap::entry` guard so the
    /// second caller observes the first caller's reservation.
    #[must_use]
    pub fn try_reserve(&self, key: Arc<str>, now_ms: i64, expires_ms: i64) -> bool {
        use dashmap::mapref::entry::Entry;
        match self.map.entry(key) {
            Entry::Occupied(mut occupied) => {
                if *occupied.get() > now_ms {
                    // Active window — caller is rate-limited.
                    false
                } else {
                    // Expired entry — reuse the slot with new expiry.
                    *occupied.get_mut() = expires_ms;
                    true
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(expires_ms);
                true
            }
        }
    }

    /// Release a reservation made by [`Self::try_reserve`] when the followup
    /// work (e.g. `try_send`) fails. Only removes the entry if it still
    /// holds the exact `expires_ms` we reserved — protects against racing
    /// with a later successful reservation that bumped the expiry.
    pub fn rollback(&self, key: &Arc<str>, expires_ms: i64) {
        use dashmap::mapref::entry::Entry;
        if let Entry::Occupied(occupied) = self.map.entry(Arc::clone(key))
            && *occupied.get() == expires_ms
        {
            occupied.remove();
        }
    }

    /// Live bucket count. Cheap O(1) read across `DashMap` shards.
    #[must_use]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Purge expired buckets, then enforce `max_keys` by evicting the entries
    /// with the earliest `expires_ms` (LRU on the bucket TTL). Returns the
    /// number of entries removed.
    pub fn gc(&self, now_ms: i64, max_keys: usize) -> usize {
        let before = self.map.len();
        self.map.retain(|_k, expires_ms| *expires_ms > now_ms);

        if self.map.len() > max_keys {
            let mut entries: Vec<(Arc<str>, i64)> =
                self.map.iter().map(|e| (Arc::clone(e.key()), *e.value())).collect();
            entries.sort_by_key(|(_k, exp)| *exp);
            let to_remove = self.map.len().saturating_sub(max_keys);
            for (key, _) in entries.into_iter().take(to_remove) {
                self.map.remove(&key);
            }
        }

        before.saturating_sub(self.map.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_format_includes_separator() {
        let key = make_key("10.0.0.1", "BOT-XFF-MALFORMED-001");
        assert_eq!(&*key, "10.0.0.1#BOT-XFF-MALFORMED-001");
    }

    #[test]
    fn unclaimed_key_is_inactive() {
        let store = BucketStore::new();
        let key = make_key("1.1.1.1", "R1");
        assert!(!store.is_active(&key, 0));
    }

    #[test]
    fn claim_then_active_then_expires() {
        let store = BucketStore::new();
        let key = make_key("1.1.1.1", "R1");
        store.claim(Arc::clone(&key), 1000);
        assert!(store.is_active(&key, 500));
        assert!(!store.is_active(&key, 1500));
    }

    #[test]
    fn gc_purges_expired_entries() {
        let store = BucketStore::new();
        store.claim(make_key("a", "R"), 100);
        store.claim(make_key("b", "R"), 500);
        let removed = store.gc(200, 100);
        assert_eq!(removed, 1);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn gc_evicts_oldest_when_over_cap() {
        let store = BucketStore::new();
        for i in 0..15 {
            store.claim(make_key(&format!("ip{i}"), "R"), 1_000 + i64::from(i));
        }
        assert_eq!(store.len(), 15);
        let removed = store.gc(0, 10);
        assert_eq!(removed, 5);
        assert_eq!(store.len(), 10);
    }

    #[test]
    fn try_reserve_succeeds_on_first_call() {
        let store = BucketStore::new();
        let key = make_key("ip1", "R");
        assert!(store.try_reserve(Arc::clone(&key), 100, 1_100));
        assert!(store.is_active(&key, 200));
    }

    #[test]
    fn try_reserve_returns_false_when_active() {
        let store = BucketStore::new();
        let key = make_key("ip1", "R");
        assert!(store.try_reserve(Arc::clone(&key), 100, 1_100));
        // Second concurrent attempt within window must observe reservation.
        assert!(!store.try_reserve(Arc::clone(&key), 200, 1_200));
    }

    #[test]
    fn try_reserve_reuses_expired_slot() {
        let store = BucketStore::new();
        let key = make_key("ip1", "R");
        assert!(store.try_reserve(Arc::clone(&key), 100, 1_100));
        // Window passes — next try_reserve at later `now_ms` succeeds.
        assert!(store.try_reserve(Arc::clone(&key), 2_000, 3_000));
    }

    #[test]
    fn rollback_removes_reservation_when_expires_matches() {
        let store = BucketStore::new();
        let key = make_key("ip1", "R");
        assert!(store.try_reserve(Arc::clone(&key), 100, 1_100));
        store.rollback(&key, 1_100);
        assert!(!store.is_active(&key, 150));
    }

    #[test]
    fn rollback_noop_when_expires_was_bumped() {
        // Simulates: T1 reserves with expires=1_100, fails try_send and calls
        // rollback. Meanwhile T2 reserved successfully with expires=2_000.
        // T1's rollback must NOT erase T2's reservation.
        let store = BucketStore::new();
        let key = make_key("ip1", "R");
        assert!(store.try_reserve(Arc::clone(&key), 100, 1_100));
        // Simulate T2 bumping the slot.
        store.claim(Arc::clone(&key), 2_000);
        // T1 rolls back with its old expires — should NOT remove T2's entry.
        store.rollback(&key, 1_100);
        assert!(store.is_active(&key, 150));
    }

    #[test]
    fn try_reserve_is_atomic_under_concurrent_callers() {
        // 100 threads race on the same key. Exactly one must observe true;
        // the other 99 must observe false.
        use std::sync::Arc as StdArc;
        use std::thread;

        let store = StdArc::new(BucketStore::new());
        let key = make_key("hot", "R");
        let barrier = StdArc::new(std::sync::Barrier::new(100));
        let mut handles = Vec::with_capacity(100);
        for _ in 0..100 {
            let store = StdArc::clone(&store);
            let key = Arc::clone(&key);
            let barrier = StdArc::clone(&barrier);
            handles.push(thread::spawn(move || {
                barrier.wait();
                store.try_reserve(key, 100, 1_100)
            }));
        }
        let wins = handles
            .into_iter()
            .map(|h| h.join().expect("thread"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(wins, 1, "exactly one reservation must succeed under race");
    }

    #[test]
    fn now_epoch_ms_is_monotonic_within_call() {
        let a = now_epoch_ms();
        let b = now_epoch_ms();
        assert!(b >= a, "wall clock must not run backward across two calls");
    }
}
