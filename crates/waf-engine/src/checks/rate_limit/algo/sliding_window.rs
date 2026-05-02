//! Sliding-window counter (pure logic, no I/O).
//!
//! Two-bucket weighted approximation: estimated load =
//! `curr_count + prev_count * (1 - elapsed_in_curr / window)`.
//! Cheaper than a full request-timestamp log, accurate within one bucket.

use crate::checks::rate_limit::LimitCfg;

/// Per-key sliding-window state.
#[derive(Clone, Copy, Debug)]
pub struct SlidingWindowState {
    /// Requests counted in the current window.
    pub curr_count: u32,
    /// Requests counted in the previous (immediately preceding) window.
    pub prev_count: u32,
    /// Epoch-ms start of the current window (aligned to `window_secs` grid).
    pub curr_window_start_ms: i64,
}

impl SlidingWindowState {
    /// Create state with empty counters, aligned to the grid containing `now_ms`.
    pub fn new(now_ms: i64, window_secs: u32) -> Self {
        let win_ms = i64::from(window_secs) * 1000;
        Self {
            curr_count: 0,
            prev_count: 0,
            curr_window_start_ms: align_floor(now_ms, win_ms),
        }
    }

    /// Roll window if past boundary, then weighted-estimate and admit/reject.
    /// Returns `true` if request fits within `window_limit`.
    pub fn try_consume(&mut self, cfg: &LimitCfg, now_ms: i64) -> bool {
        let win_ms = i64::from(cfg.window_secs) * 1000;
        let bucket_now = align_floor(now_ms, win_ms);
        let advance = ((bucket_now - self.curr_window_start_ms) / win_ms).max(0);
        match advance {
            0 => {}
            1 => {
                // Advanced exactly one window — current becomes previous.
                self.prev_count = self.curr_count;
                self.curr_count = 0;
                self.curr_window_start_ms = bucket_now;
            }
            _ => {
                // Skipped >1 window — both counters stale, reset.
                self.prev_count = 0;
                self.curr_count = 0;
                self.curr_window_start_ms = bucket_now;
            }
        }
        let elapsed_in_curr = (now_ms - self.curr_window_start_ms).max(0);
        // i64 → f64 lossy past 2^53; fine for window deltas (≤ window_secs * 1000).
        #[allow(clippy::cast_precision_loss)]
        let weight_prev = 1.0 - (elapsed_in_curr as f64 / win_ms as f64).clamp(0.0, 1.0);
        let estimated = f64::from(self.prev_count).mul_add(weight_prev, f64::from(self.curr_count));
        if (estimated + 1.0) > f64::from(cfg.window_limit) {
            false
        } else {
            self.curr_count = self.curr_count.saturating_add(1);
            true
        }
    }
}

/// Floor `t` to the nearest multiple of `grid` (grid > 0).
/// Handles negative `t` correctly (Euclidean floor).
const fn align_floor(t: i64, grid: i64) -> i64 {
    t.div_euclid(grid) * grid
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(window_secs: u32, limit: u32) -> LimitCfg {
        LimitCfg {
            burst_capacity: 100,
            burst_refill_per_s: 10.0,
            window_secs,
            window_limit: limit,
        }
    }

    #[test]
    fn under_limit_allows() {
        let cfg = cfg(60, 5);
        let mut s = SlidingWindowState::new(0, 60);
        for _ in 0..5 {
            assert!(s.try_consume(&cfg, 0));
        }
    }

    #[test]
    fn over_limit_blocks() {
        let cfg = cfg(60, 3);
        let mut s = SlidingWindowState::new(0, 60);
        assert!(s.try_consume(&cfg, 0));
        assert!(s.try_consume(&cfg, 0));
        assert!(s.try_consume(&cfg, 0));
        assert!(!s.try_consume(&cfg, 0)); // 4th over limit=3
    }

    #[test]
    fn window_roll_carries_prev_count() {
        let cfg = cfg(10, 100);
        let mut s = SlidingWindowState::new(0, 10);
        for _ in 0..50 {
            s.try_consume(&cfg, 0);
        }
        // Advance one window; prev=50, curr=0
        s.try_consume(&cfg, 10_000);
        assert_eq!(s.prev_count, 50);
        assert_eq!(s.curr_count, 1);
    }

    #[test]
    fn multi_window_skip_clears_prev() {
        let cfg = cfg(10, 100);
        let mut s = SlidingWindowState::new(0, 10);
        for _ in 0..50 {
            s.try_consume(&cfg, 0);
        }
        // Skip 5 windows — both counters must reset.
        s.try_consume(&cfg, 50_000);
        assert_eq!(s.prev_count, 0);
        assert_eq!(s.curr_count, 1);
    }

    #[test]
    fn weight_decays_toward_window_end() {
        // Fill prev fully, then probe weight at start vs end of curr.
        let cfg = cfg(10, 100);
        let mut s = SlidingWindowState {
            curr_count: 0,
            prev_count: 80,
            curr_window_start_ms: 10_000,
        };
        // Near start of curr (weight≈1.0): estimated ≈ 80 → allowed (80+1 < 100).
        assert!(s.try_consume(&cfg, 10_001));
        s.curr_count = 0; // reset for second probe
        // Near end of curr (weight≈0.0): estimated ≈ 0 → allowed.
        assert!(s.try_consume(&cfg, 19_999));
    }

    #[test]
    fn negative_clock_skew_does_not_panic() {
        let cfg = cfg(10, 100);
        let mut s = SlidingWindowState::new(1_000_000, 10);
        // now_ms before window start
        let _ = s.try_consume(&cfg, 0);
    }
}
