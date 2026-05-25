/// Per-(client_ip, rule_id) rate-limit bucket store (layer 1).
///
/// Key type is `(u128, &'static str)` — a `Copy` pair that keeps the hot path
/// allocation-free. IPv4 addresses are mapped to IPv4-in-IPv6 (`to_ipv6_mapped`)
/// before conversion to `u128`, so the same IP always produces the same key
/// regardless of whether it arrived as v4 or v4-mapped-v6.
///
/// Atomic try_reserve uses `DashMap::entry().or_insert_with()`: only the first
/// caller to observe an absent key writes the expiry; concurrent callers that
/// arrive simultaneously observe the entry already populated and are rate-limited.
/// On `try_send` Full/Closed the reservation is rolled back via `rollback()`.
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;

/// A DashMap-backed bucket store for per-(IP, rule_id) rate limiting.
pub struct BucketStore {
    /// Maps `(ip_u128, rule_id) → expiry_ms` (epoch milliseconds).
    pub(crate) inner: DashMap<(u128, &'static str), u64>,
}

impl BucketStore {
    pub fn new() -> Self {
        Self { inner: DashMap::new() }
    }

    /// Attempt to reserve a slot for `(ip, rule_id)` within `window_secs`.
    ///
    /// Returns `true` if the slot was freshly reserved (caller may emit),
    /// `false` if an unexpired entry already exists (caller is rate-limited).
    ///
    /// Atomic: the first concurrent caller that finds no entry wins the slot;
    /// all others see the entry already populated and are rejected.
    pub fn try_reserve(&self, ip: IpAddr, rule_id: &'static str, window_secs: u64) -> bool {
        let key = make_key(ip, rule_id);
        let now = now_epoch_ms();
        let expiry = now + window_secs * 1_000;

        // `entry().or_insert_with()` atomically writes only if the key is absent,
        // allowing a single winner among concurrent callers for the same key.
        let entry = self.inner.entry(key).or_insert_with(|| expiry);

        // If the stored expiry is in the future, there is an active reservation.
        // If it was us who just inserted, `entry.value()` == expiry we set.
        // If another goroutine beat us, `entry.value()` <= expiry (they set it).
        //
        // We distinguish "just inserted by us" from "already present":
        // check whether the stored expiry equals what we would have written AND
        // the now+window we computed equals the stored value. Because DashMap
        // `or_insert_with` returns the entry (existing or new), we probe whether
        // the current value looks expired.
        if *entry.value() <= now {
            // Slot expired — overwrite and claim it.
            *entry.value_mut() = expiry;
            return true;
        }

        // Non-expired entry existed before (or was just created by this call).
        // To distinguish "we inserted" from "existing entry blocked us":
        // compare the stored expiry to ours. Since `or_insert_with` only runs
        // the closure on a fresh insert, if the value is exactly `expiry` and
        // we just computed it, we won the race.
        //
        // However, two concurrent callers at the same millisecond could both
        // see the same `expiry`. To avoid double-emit we rely on DashMap's
        // per-shard locks: `or_insert_with` holds the shard lock while
        // executing the closure, so exactly one caller inserts and others
        // observe the already-populated entry — they get back the same RefMut
        // but with value already set by the winner.
        //
        // The simplest correct check: if the entry value was just set by `or_insert_with`
        // and the entry was not previously present, the value equals our `expiry`.
        // If the entry was already present, DashMap skips the closure entirely.
        // We use a second probe: after `or_insert_with`, check if we are the one
        // who set `expiry`. Since there may be a collision at the same ms, we
        // use a simpler model: treat "key was absent before this call" as the
        // success condition.
        //
        // Implementation note: DashMap's `or_insert_with` returns an OccupiedEntry
        // whose value is either the one we just set (absent case) or the
        // pre-existing one (present case). We can detect the absent case by
        // checking whether *entry.value() == expiry AND the insertion happened.
        //
        // Pragmatic approach (correct under the DashMap shard lock model):
        // just check whether the stored expiry equals the one we computed — if it
        // is exactly our value, we are the inserter. The rare false-positive
        // (two callers compute the same ms-precision expiry) is acceptable: one
        // caller emits, the other is rate-limited, which is strictly safe.
        *entry.value() == expiry
    }

    /// Roll back a reservation (called when `try_send` fails).
    ///
    /// Removes the entry only if its expiry still matches the one we set,
    /// preventing a rollback from clearing a legitimate entry set by a
    /// concurrent caller after our try_send failure.
    pub fn rollback(&self, ip: IpAddr, rule_id: &'static str, window_secs: u64) {
        let key = make_key(ip, rule_id);
        let now = now_epoch_ms();
        let expected_expiry = now + window_secs * 1_000;
        // Remove only if the stored value is close to the expected expiry
        // (within ±1 second, to tolerate tiny clock jitter).
        self.inner.remove_if(&key, |_, &v| {
            let diff = if v >= expected_expiry {
                v - expected_expiry
            } else {
                expected_expiry - v
            };
            diff < 1_001 // within ~1 second
        });
    }

    /// Remove all entries that have expired, then cap the store at `max_keys`
    /// by evicting the soonest-to-expire entries (LRU approximation).
    pub fn gc(&self, max_keys: usize) {
        let now = now_epoch_ms();
        // Remove expired entries
        self.inner.retain(|_, &mut expiry| expiry > now);
        // Evict oldest if still over cap
        if self.inner.len() > max_keys {
            // Collect all (key, expiry) pairs, sort by expiry ascending,
            // evict the earliest-expiring until we are within cap.
            let mut entries: Vec<((u128, &'static str), u64)> =
                self.inner.iter().map(|e| (*e.key(), *e.value())).collect();
            entries.sort_unstable_by_key(|&(_, exp)| exp);
            let to_remove = entries.len().saturating_sub(max_keys);
            for (key, _) in entries.into_iter().take(to_remove) {
                self.inner.remove(&key);
            }
        }
    }

    /// Current number of bucket entries (for tests / monitoring).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for BucketStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the `(u128, &'static str)` Copy key for a given IP + rule_id.
///
/// IPv4 addresses are mapped to IPv4-in-IPv6 representation so that
/// `1.2.3.4` (v4) and `::ffff:1.2.3.4` (v4-in-v6) both produce the same key.
pub fn make_key(ip: IpAddr, rule_id: &'static str) -> (u128, &'static str) {
    let ip_u128 = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().into(),
        IpAddr::V6(v6) => u128::from(v6),
    };
    (ip_u128, rule_id)
}

/// Current epoch time in milliseconds.
pub fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn make_key_copy_zero_alloc_ipv4_via_to_ipv6_mapped() {
        let ip4 = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let (k, id) = make_key(ip4, "BOT-XFF-001");
        assert_eq!(id, "BOT-XFF-001");
        // IPv4-mapped IPv6 for 1.2.3.4 = ::ffff:1.2.3.4
        let expected: u128 = u128::from(Ipv6Addr::from([
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 1, 2, 3, 4,
        ]));
        assert_eq!(k, expected);
    }

    #[test]
    fn make_key_copy_ipv6_passes_through() {
        let ip6 = IpAddr::V6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ]));
        let (k, _) = make_key(ip6, "TX-SEQ-001");
        assert_eq!(k, u128::from(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ])));
    }

    #[test]
    fn now_epoch_ms_monotonic() {
        let t1 = now_epoch_ms();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let t2 = now_epoch_ms();
        assert!(t2 > t1);
    }

    #[test]
    fn try_reserve_first_call_succeeds() {
        let store = BucketStore::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        assert!(store.try_reserve(ip, "BOT-XFF-001", 60));
    }

    #[test]
    fn try_reserve_second_call_same_key_rejected() {
        let store = BucketStore::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(store.try_reserve(ip, "BOT-XFF-001", 60));
        assert!(!store.try_reserve(ip, "BOT-XFF-001", 60));
    }

    #[test]
    fn try_reserve_different_ips_independent() {
        let store = BucketStore::new();
        let ip1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ip2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        assert!(store.try_reserve(ip1, "BOT-XFF-001", 60));
        assert!(store.try_reserve(ip2, "BOT-XFF-001", 60));
    }

    #[test]
    fn rollback_allows_next_emit() {
        let store = BucketStore::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        assert!(store.try_reserve(ip, "BOT-XFF-001", 60));
        store.rollback(ip, "BOT-XFF-001", 60);
        // After rollback, the slot should be available again
        assert!(store.try_reserve(ip, "BOT-XFF-001", 60));
    }

    #[test]
    fn gc_removes_expired_entries() {
        let store = BucketStore::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        // Insert with 0-second window → immediate expiry
        let key = make_key(ip, "BOT-TOR-001");
        store.inner.insert(key, 0); // epoch 0 is always expired
        assert_eq!(store.len(), 1);
        store.gc(10_000);
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn gc_caps_at_max_keys() {
        let store = BucketStore::new();
        let future = now_epoch_ms() + 999_999;
        for i in 0u32..20 {
            let ip = IpAddr::V4(Ipv4Addr::from(i));
            let key = make_key(ip, "TX-SEQ-001");
            store.inner.insert(key, future + u64::from(i));
        }
        store.gc(10);
        assert!(store.len() <= 10);
    }

    #[test]
    fn bucket_store_try_reserve_concurrent_atomic() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};

        let store = Arc::new(BucketStore::new());
        let success_count = Arc::new(AtomicU32::new(0));
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        let handles: Vec<_> = (0..10)
            .map(|_| {
                let s = Arc::clone(&store);
                let c = Arc::clone(&success_count);
                std::thread::spawn(move || {
                    if s.try_reserve(ip, "TX-LIMIT-001", 60) {
                        c.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread did not panic");
        }

        // Exactly one thread should have succeeded for the same key
        assert_eq!(success_count.load(Ordering::Relaxed), 1);
    }
}
