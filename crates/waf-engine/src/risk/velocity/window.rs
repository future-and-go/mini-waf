//! Sliding-window velocity tracker.
//!
//! 60×1s ring buffer per `RiskKey`. Tracks request rate over the last minute.
//! When threshold is breached (e.g., >100 req/min on Critical-tier), emits +25 delta.
//!
//! Uses atomic operations for lock-free bucket updates. O(1) amortized.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use dashmap::DashMap;

use crate::risk::key::RiskKey;
use crate::risk::state::{Contributor, ContributorKind};

/// Risk delta when velocity threshold is breached.
pub const VELOCITY_THRESHOLD_DELTA: i16 = 25;

/// Number of buckets in the ring (one per second, one minute window).
pub const BUCKET_COUNT: usize = 60;

/// Default velocity threshold (requests per minute).
pub const DEFAULT_THRESHOLD: u32 = 100;

/// A single time bucket in the ring.
#[derive(Debug)]
struct Bucket {
    /// Unix timestamp (seconds) this bucket represents.
    timestamp: AtomicU64,
    /// Request count in this bucket.
    count: AtomicU32,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            timestamp: AtomicU64::new(0),
            count: AtomicU32::new(0),
        }
    }
}

/// Sliding window for a single actor.
#[derive(Debug)]
pub struct SlidingWindow {
    buckets: [Bucket; BUCKET_COUNT],
}

impl Default for SlidingWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl SlidingWindow {
    #[must_use]
    pub fn new() -> Self {
        Self {
            buckets: std::array::from_fn(|_| Bucket::default()),
        }
    }

    /// Record a request at the given timestamp (seconds).
    ///
    /// Returns the current request count over the last minute.
    #[allow(clippy::indexing_slicing)] // idx is always < BUCKET_COUNT due to modulo
    pub fn record(&self, now_sec: u64) -> u32 {
        #[allow(clippy::cast_possible_truncation)] // BUCKET_COUNT=60, always fits in usize
        let idx = (now_sec % BUCKET_COUNT as u64) as usize;
        let bucket = &self.buckets[idx];

        let stored_ts = bucket.timestamp.load(Ordering::Acquire);

        if stored_ts == now_sec {
            // Same second — increment
            bucket.count.fetch_add(1, Ordering::Relaxed);
        } else {
            // New second — reset bucket
            bucket.timestamp.store(now_sec, Ordering::Release);
            bucket.count.store(1, Ordering::Release);
        }

        self.count_in_window(now_sec)
    }

    /// Count requests in the last `BUCKET_COUNT` seconds.
    #[must_use]
    pub fn count_in_window(&self, now_sec: u64) -> u32 {
        let cutoff = now_sec.saturating_sub(BUCKET_COUNT as u64);
        let mut total = 0u32;

        for bucket in &self.buckets {
            let ts = bucket.timestamp.load(Ordering::Acquire);
            if ts > cutoff {
                total = total.saturating_add(bucket.count.load(Ordering::Relaxed));
            }
        }

        total
    }
}

/// Velocity store: tracks sliding windows per `RiskKey`.
#[derive(Debug, Default)]
pub struct VelocityStore {
    windows: DashMap<RiskKey, SlidingWindow>,
    /// Threshold for triggering velocity alert.
    threshold: u32,
}

impl VelocityStore {
    #[must_use]
    pub fn new(threshold: u32) -> Self {
        Self {
            windows: DashMap::new(),
            threshold,
        }
    }

    /// Record a request and check if threshold is breached.
    ///
    /// Returns `Some(count)` if threshold breached, `None` otherwise.
    pub fn record(&self, key: &RiskKey, now_ms: i64) -> Option<u32> {
        #[allow(clippy::cast_sign_loss)]
        let now_sec = (now_ms / 1000) as u64;

        let count = self.windows.entry(key.clone()).or_default().record(now_sec);
        if count > self.threshold { Some(count) } else { None }
    }

    /// Get current request count for a key without recording.
    #[must_use]
    pub fn peek(&self, key: &RiskKey, now_ms: i64) -> u32 {
        #[allow(clippy::cast_sign_loss)]
        let now_sec = (now_ms / 1000) as u64;

        self.windows.get(key).map_or(0, |w| w.count_in_window(now_sec))
    }

    /// Purge entries that have been idle (all buckets expired).
    pub fn purge_idle(&self, now_ms: i64) -> usize {
        #[allow(clippy::cast_sign_loss)]
        let now_sec = (now_ms / 1000) as u64;
        let cutoff = now_sec.saturating_sub(BUCKET_COUNT as u64);
        let mut purged = 0;

        self.windows.retain(|_, window| {
            let has_active = window
                .buckets
                .iter()
                .any(|b| b.timestamp.load(Ordering::Relaxed) > cutoff);
            if !has_active {
                purged += 1;
            }
            has_active
        });

        purged
    }

    /// Number of tracked actors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.windows.len()
    }

    /// Check if store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.windows.is_empty()
    }
}

/// Evaluate velocity and return a contributor if threshold breached.
#[must_use]
pub fn evaluate(store: &VelocityStore, key: &RiskKey, now_ms: i64) -> Option<Contributor> {
    store
        .record(key, now_ms)
        .map(|_count| Contributor::new(ContributorKind::Anomaly, VELOCITY_THRESHOLD_DELTA, now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_key() -> RiskKey {
        RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    }

    #[test]
    fn sliding_window_counts_correctly() {
        let window = SlidingWindow::new();
        let now = 1000u64;

        // Record 5 requests at same second
        for _ in 0..5 {
            window.record(now);
        }

        assert_eq!(window.count_in_window(now), 5);
    }

    #[test]
    fn sliding_window_expires_old_buckets() {
        let window = SlidingWindow::new();

        // Record at t=0
        window.record(0);

        // At t=61, the bucket at t=0 should be expired
        let count = window.count_in_window(61);
        assert_eq!(count, 0);
    }

    #[test]
    fn sliding_window_multiple_seconds() {
        let window = SlidingWindow::new();

        // Record across multiple seconds
        window.record(100);
        window.record(101);
        window.record(101);
        window.record(102);

        assert_eq!(window.count_in_window(102), 4);
    }

    #[test]
    fn velocity_store_threshold_breach() {
        let store = VelocityStore::new(5); // Low threshold for testing
        let key = make_key();
        let now_ms = 1_000_000i64;

        // Record 5 requests (at threshold)
        for _ in 0..5 {
            assert!(store.record(&key, now_ms).is_none());
        }

        // 6th request breaches threshold
        assert!(store.record(&key, now_ms).is_some());
    }

    #[test]
    fn velocity_store_separate_keys() {
        let store = VelocityStore::new(3);
        let key1 = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let key2 = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        let now_ms = 1_000_000i64;

        // 4 requests from key1 (breaches)
        for _ in 0..4 {
            store.record(&key1, now_ms);
        }

        // key2 should still be clean
        assert!(store.record(&key2, now_ms).is_none());
    }

    #[test]
    fn velocity_store_purge_idle() {
        let store = VelocityStore::new(100);
        let key = make_key();

        // Record at t=0
        store.record(&key, 0);
        assert_eq!(store.len(), 1);

        // Purge at t=61s (61000ms) — should remove idle entry
        let purged = store.purge_idle(61_000);
        assert_eq!(purged, 1);
        assert!(store.is_empty());
    }

    #[test]
    fn evaluate_returns_contributor_on_breach() {
        let store = VelocityStore::new(2);
        let key = make_key();
        let now_ms = 1_000_000i64;

        // First two requests: no breach
        assert!(evaluate(&store, &key, now_ms).is_none());
        assert!(evaluate(&store, &key, now_ms).is_none());

        // Third request: breach
        let result = evaluate(&store, &key, now_ms);
        assert!(result.is_some());
        assert_eq!(result.unwrap().delta, VELOCITY_THRESHOLD_DELTA);
    }
}
