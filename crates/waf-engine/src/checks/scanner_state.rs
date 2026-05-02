//! Per-IP sliding-window state for FR-019 scanner detection.
//!
//! Tracks two signals: distinct paths visited (endpoint enumeration) and
//! OPTIONS requests issued (preflight abuse). Both windows share the same
//! length, sourced from `defense_config.scanner_window_secs`.
//!
//! State is bounded: when the per-IP map exceeds `max_entries`, the oldest
//! 10 percent (by last-touched timestamp) are evicted. This prevents an
//! attacker rotating IPv6 /64 prefixes from OOM-ing the engine — Red Team
//! Finding #6.
//!
//! Time is read through an injected [`Clock`] so tests can advance windows
//! deterministically without sleeping (Validation Q7).

// `duration_suboptimal_units` flags `from_secs(60)` etc. across the test
// bodies; we keep the literals as seconds for readability against the
// `scanner_window_secs` config name. `significant_drop_tightening` flags
// the DashMap entry held during a Mutex lock — restructuring to drop the
// entry RefMut early would require owning the inner `Arc<Mutex<…>>` per
// record. `redundant_clone` fires on test fixtures.
#![allow(
    clippy::duration_suboptimal_units,
    clippy::significant_drop_tightening,
    clippy::redundant_clone
)]

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

use super::Clock;

/// Per-IP record: ring buffer of path hits + incremental distinct-path
/// index + ring buffer of OPTIONS timestamps, plus the wall-clock instant
/// of the most recent touch (used by eviction).
struct IpRecord {
    /// `(timestamp, path)` pairs — newest at the back. Pruned on every push
    /// to keep the buffer bounded by the active window. Duplicate paths ARE
    /// appended (so window-expiry is cheap) but deduped at count-time via
    /// `paths_set`.
    paths: VecDeque<(Instant, String)>,
    /// `path → count` of occurrences currently in `paths`. Avoids the
    /// per-request O(N) rebuild `HashSet<&str>::from_iter` paid on every
    /// `distinct_paths()` call — under sustained one-IP-one-path traffic
    /// the `VecDeque` grows to window-sized, and the rebuild was O(N) per
    /// request = O(N²) over the window.
    paths_set: HashMap<String, usize>,
    /// Timestamps of OPTIONS requests within the active window.
    options: VecDeque<Instant>,
    last_touched: Instant,
}

impl IpRecord {
    fn new(now: Instant) -> Self {
        Self {
            paths: VecDeque::new(),
            paths_set: HashMap::new(),
            options: VecDeque::new(),
            last_touched: now,
        }
    }

    /// Push a path hit and update the incremental distinct-path index.
    fn push_path(&mut self, now: Instant, path: &str) {
        // Bump or insert; only the first occurrence contributes to
        // distinct-path count.
        *self.paths_set.entry(path.to_string()).or_insert(0) += 1;
        self.paths.push_back((now, path.to_string()));
        // Hard cap to bound per-record memory under sustained abuse —
        // an attacker whose request stream stays inside one window can
        // otherwise grow `paths` by req-rate × window-len. The distinct
        // count we care about is `paths_set.len()`, so the deque only
        // needs enough headroom to roll old entries out of the window.
        // (Pre-merge Finding I3.)
        while self.paths.len() > PATHS_HARD_CAP {
            let Some((_, old_path)) = self.paths.pop_front() else {
                break;
            };
            if let Some(count) = self.paths_set.get_mut(&old_path) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.paths_set.remove(&old_path);
                }
            }
        }
    }

    /// Drop entries older than `window` ago, decrementing / removing from
    /// the distinct-path index as entries leave the window.
    fn prune(&mut self, now: Instant, window: Duration) {
        let cutoff = now.checked_sub(window).unwrap_or(now);
        while let Some((t, _)) = self.paths.front() {
            if *t >= cutoff {
                break;
            }
            let Some((_, old_path)) = self.paths.pop_front() else {
                break;
            };
            if let Some(count) = self.paths_set.get_mut(&old_path) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.paths_set.remove(&old_path);
                }
            }
        }
        while self.options.front().is_some_and(|t| *t < cutoff) {
            self.options.pop_front();
        }
    }

    /// O(1) — just the length of the distinct-path index.
    fn distinct_paths(&self) -> usize {
        self.paths_set.len()
    }
}

/// How many `record_*` calls over `max_entries` must happen before we pay
/// the O(N log N) eviction scan. Amortizes the cost so an attacker spamming
/// unique IPs past the cap cannot turn eviction itself into a `DoS` amplifier.
const EVICT_INTERVAL: usize = 1024;

/// Hard cap on per-IP `IpRecord.paths` length. Caps memory cost of any
/// single attacker IP at `O(PATHS_HARD_CAP × avg_path_len)` — distinct-path
/// detection reads `paths_set.len()` so the deque only needs slack to roll
/// old entries out by time-window.
const PATHS_HARD_CAP: usize = 1024;

pub struct ScannerState {
    per_ip: Arc<DashMap<IpAddr, Mutex<IpRecord>>>,
    max_entries: usize,
    /// Counts calls while over capacity — only every `EVICT_INTERVAL`'th
    /// triggers an actual eviction sweep.
    evict_ticker: AtomicUsize,
    clock: Arc<dyn Clock>,
}

impl ScannerState {
    pub fn new(max_entries: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            per_ip: Arc::new(DashMap::new()),
            max_entries,
            evict_ticker: AtomicUsize::new(0),
            clock,
        }
    }

    /// Record one path visit and return the current distinct-path count
    /// inside `window` for this client.
    pub fn record_path(&self, ip: IpAddr, path: &str, window: Duration) -> usize {
        self.evict_if_over_cap();
        let now = self.clock.now();
        let entry = self.per_ip.entry(ip).or_insert_with(|| Mutex::new(IpRecord::new(now)));
        let mut rec = entry.lock();
        rec.last_touched = now;
        rec.push_path(now, path);
        rec.prune(now, window);
        rec.distinct_paths()
    }

    /// Record one OPTIONS request and return the current OPTIONS count
    /// inside `window` for this client.
    pub fn record_options(&self, ip: IpAddr, window: Duration) -> usize {
        self.evict_if_over_cap();
        let now = self.clock.now();
        let entry = self.per_ip.entry(ip).or_insert_with(|| Mutex::new(IpRecord::new(now)));
        let mut rec = entry.lock();
        rec.last_touched = now;
        rec.options.push_back(now);
        rec.prune(now, window);
        rec.options.len()
    }

    /// Drop the oldest 10 percent of entries (by `last_touched`) — but only
    /// once every [`EVICT_INTERVAL`] calls while over cap. Amortizes the
    /// O(N log N) sort so an attacker cycling IPv6 prefixes cannot turn
    /// eviction itself into a CPU amplifier.
    fn evict_if_over_cap(&self) {
        if self.per_ip.len() <= self.max_entries {
            return;
        }
        let tick = self.evict_ticker.fetch_add(1, Ordering::Relaxed);
        if !tick.is_multiple_of(EVICT_INTERVAL) {
            return;
        }
        let mut ages: Vec<(IpAddr, Instant)> = self
            .per_ip
            .iter()
            .map(|kv| (*kv.key(), kv.value().lock().last_touched))
            .collect();
        // Drop enough to come back below cap, capped at 10 percent of current size.
        let over = self.per_ip.len().saturating_sub(self.max_entries);
        let drop_n = over.max(ages.len() / 10).min(ages.len());
        if drop_n == 0 {
            return;
        }
        // Partial-sort: we only need the `drop_n` smallest-by-timestamp
        // entries at the front of the vec; full sort is O(N log N) and makes
        // the eviction path its own CPU-DoS primitive under IPv6 /64
        // rotation. `select_nth_unstable_by_key` is O(N) average.
        if drop_n < ages.len() {
            ages.select_nth_unstable_by_key(drop_n - 1, |(_, t)| *t);
        }
        for (ip, _) in ages.into_iter().take(drop_n) {
            self.per_ip.remove(&ip);
        }
    }

    /// Drop every entry whose `last_touched` is older than `cutoff`. Run by
    /// a periodic prune task in production.
    pub fn prune_older_than(&self, cutoff: Instant) {
        self.per_ip.retain(|_, rec| rec.lock().last_touched >= cutoff);
    }

    pub fn len(&self) -> usize {
        self.per_ip.len()
    }

    pub fn is_empty(&self) -> bool {
        self.per_ip.is_empty()
    }
}

// `manual_duration_constructor` from the workspace `nursery` lints fires on
// every `Duration::from_secs(60)` / `from_secs(120)` we use here — clippy
// would prefer multiplying-by-60 idioms. The literals stay readable as-is.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::test_clock::MockClock;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn record_path_returns_growing_distinct_count() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock.clone());
        assert_eq!(s.record_path(ip("1.1.1.1"), "/a", Duration::from_secs(60)), 1);
        assert_eq!(s.record_path(ip("1.1.1.1"), "/b", Duration::from_secs(60)), 2);
        assert_eq!(s.record_path(ip("1.1.1.1"), "/c", Duration::from_secs(60)), 3);
    }

    #[test]
    fn duplicate_paths_count_once() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock.clone());
        for _ in 0..5 {
            s.record_path(ip("1.1.1.1"), "/same", Duration::from_secs(60));
        }
        assert_eq!(s.record_path(ip("1.1.1.1"), "/same", Duration::from_secs(60)), 1);
    }

    #[test]
    fn distinct_paths_window_expires() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock.clone());
        s.record_path(ip("1.1.1.1"), "/a", Duration::from_secs(60));
        s.record_path(ip("1.1.1.1"), "/b", Duration::from_secs(60));
        clock.advance(Duration::from_secs(120));
        // Both prior entries are now outside the window; new entry is
        // alone in the buffer.
        assert_eq!(s.record_path(ip("1.1.1.1"), "/c", Duration::from_secs(60)), 1);
    }

    #[test]
    fn options_count_grows_then_window_expires() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock.clone());
        for _ in 0..10 {
            s.record_options(ip("1.1.1.1"), Duration::from_secs(60));
        }
        assert_eq!(s.record_options(ip("1.1.1.1"), Duration::from_secs(60)), 11);
        clock.advance(Duration::from_secs(120));
        assert_eq!(s.record_options(ip("1.1.1.1"), Duration::from_secs(60)), 1);
    }

    #[test]
    fn per_ip_isolation() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock.clone());
        for i in 0..5 {
            s.record_path(ip("1.1.1.1"), &format!("/p{i}"), Duration::from_secs(60));
        }
        // Different IP starts fresh.
        assert_eq!(s.record_path(ip("2.2.2.2"), "/x", Duration::from_secs(60)), 1);
    }

    #[test]
    fn caps_at_max_entries_eventually() {
        // Eviction is amortized (every EVICT_INTERVAL calls while over cap) to
        // prevent the evict-sweep itself being a DoS vector. Test that size
        // stays bounded by (max + EVICT_INTERVAL) — the worst-case headroom —
        // and drops back to ~max once an eviction sweep fires.
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(100, clock.clone());
        let total = 100 + EVICT_INTERVAL + 100;
        for i in 0..total {
            s.record_path(
                ip(&format!("10.{}.{}.{}", (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff)),
                "/a",
                Duration::from_secs(60),
            );
        }
        // At least one sweep fired — size is strictly below total inserted.
        assert!(s.len() < total, "no sweep fired: len={}", s.len());
        // Worst-case headroom above cap is one interval's worth.
        assert!(s.len() <= 100 + EVICT_INTERVAL, "headroom exceeded: len={}", s.len());
    }

    #[test]
    fn prune_older_than_drops_stale_entries() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock.clone());
        s.record_path(ip("1.1.1.1"), "/old", Duration::from_secs(60));
        clock.advance(Duration::from_secs(600));
        s.record_path(ip("2.2.2.2"), "/new", Duration::from_secs(60));
        let cutoff = clock.now().checked_sub(Duration::from_secs(300)).unwrap();
        s.prune_older_than(cutoff);
        assert_eq!(s.len(), 1);
    }

    #[test]
    fn empty_state_starts_at_zero() {
        let clock = Arc::new(MockClock::new());
        let s = ScannerState::new(1000, clock);
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }
}
