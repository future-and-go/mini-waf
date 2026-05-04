//! FR-011 Phase 1 — per-actor sliding-window behavioral state.
//!
//! Pure data layer. Hand-rolled fixed-array ring keeps the type alloc-free
//! (no `Vec`, no `arraydeque` workspace dep). `distinct_paths` is a
//! high-water-mark set: once 8 distinct path hashes are seen, further
//! distinct paths are ignored — bounded memory, no decay on ring evict.
//! Phase 2 classifiers read snapshots, never the live struct.

use waf_common::tier::Tier;

/// Sample ring depth — must match `BehaviorConfig::window_size` at runtime.
pub const WINDOW: usize = 16;

/// Hard cap on tracked distinct paths per actor.
pub const MAX_DISTINCT_PATHS: usize = 8;

/// Single observed request. `ts_ms` is monotonic ms since the owning
/// `Recorder`'s anchor `Instant` — NOT wall clock — so wall-clock jumps
/// can't produce negative intervals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sample {
    pub ts_ms: u64,
    pub path_hash: u64,
    pub had_referer: bool,
    pub tier: Tier,
}

/// Per-actor state. `record` is O(1); `samples()` yields oldest→newest.
#[derive(Clone, Debug)]
pub(crate) struct ActorBehavior {
    /// Ring slots. `None` only for slots not yet written (len < WINDOW).
    samples: [Option<Sample>; WINDOW],
    /// Next write index (always 0..WINDOW).
    head: usize,
    /// Live element count, saturating at WINDOW.
    len: usize,
    distinct_paths: [u64; MAX_DISTINCT_PATHS],
    distinct_paths_len: usize,
    pub updated_ms: u64,
}

impl ActorBehavior {
    pub const fn new() -> Self {
        Self {
            samples: [None; WINDOW],
            head: 0,
            len: 0,
            distinct_paths: [0; MAX_DISTINCT_PATHS],
            distinct_paths_len: 0,
            updated_ms: 0,
        }
    }

    pub fn record(&mut self, sample: Sample) {
        // `head` is always (prev_head + 1) % WINDOW so the slot exists; the
        // `if let` keeps clippy::indexing_slicing happy without a panic shim.
        if let Some(slot) = self.samples.get_mut(self.head) {
            *slot = Some(sample);
        }
        self.head = (self.head + 1) % WINDOW;
        if self.len < WINDOW {
            self.len += 1;
        }
        self.updated_ms = sample.ts_ms;

        // Linear scan over a max-8 array — cheaper than a hashset for this size.
        let already_known = self
            .distinct_paths
            .get(..self.distinct_paths_len)
            .is_some_and(|s| s.contains(&sample.path_hash));
        if !already_known && let Some(slot) = self.distinct_paths.get_mut(self.distinct_paths_len) {
            *slot = sample.path_hash;
            self.distinct_paths_len += 1;
        }
    }

    /// Iterate samples oldest → newest. `Sample: Copy`, so this is cheap.
    pub fn samples(&self) -> impl Iterator<Item = Sample> + '_ {
        let start = if self.len < WINDOW { 0 } else { self.head };
        (0..self.len).filter_map(move |i| self.samples.get((start + i) % WINDOW).copied().flatten())
    }

    /// Adjacent-sample interval iterator (yields `len-1` items). Consumed
    /// by Phase 2 burst/cadence classifiers.
    #[allow(dead_code)]
    pub fn intervals_ms(&self) -> impl Iterator<Item = u64> + '_ {
        let mut prev: Option<u64> = None;
        self.samples().filter_map(move |s| {
            let interval = prev.map(|p| s.ts_ms.saturating_sub(p));
            prev = Some(s.ts_ms);
            interval
        })
    }

    pub const fn distinct_paths_len(&self) -> usize {
        self.distinct_paths_len
    }

    /// Live sample count (≤ WINDOW). Consumed by Phase 2 classifiers.
    #[allow(dead_code)]
    pub const fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(ts: u64, path: u64) -> Sample {
        Sample {
            ts_ms: ts,
            path_hash: path,
            had_referer: false,
            tier: Tier::CatchAll,
        }
    }

    #[test]
    fn ring_wraps_at_window() {
        let mut b = ActorBehavior::new();
        for i in 0..20u64 {
            b.record(s(i, i));
        }
        assert_eq!(b.len(), WINDOW);
        let collected: Vec<_> = b.samples().map(|x| x.ts_ms).collect();
        // oldest 4 dropped → first kept ts_ms is 4
        assert_eq!(collected.first().copied(), Some(4));
        assert_eq!(collected.last().copied(), Some(19));
        assert_eq!(collected.len(), WINDOW);
    }

    #[test]
    fn distinct_paths_capped_at_eight() {
        let mut b = ActorBehavior::new();
        for i in 0..12u64 {
            b.record(s(i, i));
        }
        assert_eq!(b.distinct_paths_len(), MAX_DISTINCT_PATHS);
    }

    #[test]
    fn distinct_paths_dedup() {
        let mut b = ActorBehavior::new();
        for _ in 0..5 {
            b.record(s(0, 42));
        }
        assert_eq!(b.distinct_paths_len(), 1);
    }

    #[test]
    fn intervals_match_diffs() {
        let mut b = ActorBehavior::new();
        b.record(s(10, 1));
        b.record(s(25, 2));
        b.record(s(30, 3));
        let v: Vec<_> = b.intervals_ms().collect();
        assert_eq!(v, vec![15, 5]);
    }

    #[test]
    fn intervals_saturate_on_backwards_ts() {
        // Defensive: anchor is monotonic, but assert saturating arithmetic.
        let mut b = ActorBehavior::new();
        b.record(s(100, 1));
        b.record(s(50, 2));
        let v: Vec<_> = b.intervals_ms().collect();
        assert_eq!(v, vec![0]);
    }

    #[test]
    fn behavior_size_is_bounded() {
        // Documents the alloc-free footprint. ~600B is acceptable; the
        // assertion exists to flag accidental size blow-ups.
        let sz = std::mem::size_of::<ActorBehavior>();
        assert!(sz <= 1024, "ActorBehavior grew to {sz} bytes — investigate");
    }
}
