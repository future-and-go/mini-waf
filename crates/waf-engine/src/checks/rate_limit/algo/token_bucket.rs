//! Token-bucket burst limiter (pure logic, no I/O).
//!
//! State is 16 bytes (`f64` + `i64`) so it packs cheaply alongside the
//! sliding-window state in a single store entry.

use crate::checks::rate_limit::LimitCfg;

/// Per-key token-bucket state.
#[derive(Clone, Copy, Debug)]
pub struct TokenBucketState {
    /// Current available tokens (fractional — refill is continuous).
    pub tokens: f64,
    /// Last time `try_consume` ran, in epoch milliseconds.
    pub last_check_ms: i64,
}

impl TokenBucketState {
    /// Create a fresh, full bucket. Used on first sight of a key.
    pub fn new_full(cfg: &LimitCfg, now_ms: i64) -> Self {
        Self {
            tokens: f64::from(cfg.burst_capacity),
            last_check_ms: now_ms,
        }
    }

    /// Refill based on elapsed time, then consume one token.
    /// Returns `true` if a token was available (request allowed).
    ///
    /// Negative `elapsed` (clock skew) is clamped to zero so we never
    /// inflate the bucket from a backwards clock.
    pub fn try_consume(&mut self, cfg: &LimitCfg, now_ms: i64) -> bool {
        let delta_ms = (now_ms - self.last_check_ms).max(0);
        // i64 → f64 is lossy past 2^53 ms (~285k years); fine for wall-clock deltas.
        #[allow(clippy::cast_precision_loss)]
        let seconds = delta_ms as f64 / 1000.0;
        let refill = seconds * cfg.burst_refill_per_s;
        let capacity = f64::from(cfg.burst_capacity);
        self.tokens = (self.tokens + refill).min(capacity);
        self.last_check_ms = now_ms;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(capacity: u32, refill: f64) -> LimitCfg {
        LimitCfg {
            burst_capacity: capacity,
            burst_refill_per_s: refill,
            window_secs: 60,
            window_limit: 1_000,
        }
    }

    #[test]
    fn full_bucket_allows_capacity_then_blocks() {
        let cfg = cfg(5, 0.0); // no refill — exact capacity test
        let mut s = TokenBucketState::new_full(&cfg, 0);
        for _ in 0..5 {
            assert!(s.try_consume(&cfg, 0));
        }
        assert!(!s.try_consume(&cfg, 0));
    }

    #[test]
    fn refill_advances_with_time() {
        let cfg = cfg(10, 1.0); // 1 token/s
        let mut s = TokenBucketState {
            tokens: 0.0,
            last_check_ms: 0,
        };
        // 2.5s later → 2.5 tokens, consume 1, leaves 1.5
        assert!(s.try_consume(&cfg, 2_500));
        assert!((s.tokens - 1.5).abs() < 1e-9);
    }

    #[test]
    fn refill_saturates_at_capacity() {
        let cfg = cfg(3, 1000.0);
        let mut s = TokenBucketState {
            tokens: 0.0,
            last_check_ms: 0,
        };
        s.try_consume(&cfg, 10_000); // huge elapsed
        // capacity 3, consumed 1 → exactly 2 left, never above capacity
        assert!((s.tokens - 2.0).abs() < 1e-9);
    }

    #[test]
    fn empty_bucket_blocks_until_refill() {
        let cfg = cfg(1, 1.0);
        let mut s = TokenBucketState::new_full(&cfg, 0);
        assert!(s.try_consume(&cfg, 0));
        assert!(!s.try_consume(&cfg, 0)); // empty
        assert!(s.try_consume(&cfg, 1_000)); // refilled
    }

    #[test]
    fn negative_clock_skew_does_not_panic_or_inflate() {
        let cfg = cfg(2, 100.0);
        let mut s = TokenBucketState {
            tokens: 0.0,
            last_check_ms: 1_000_000,
        };
        // now_ms before last_check_ms — must clamp elapsed to 0
        let allowed = s.try_consume(&cfg, 0);
        assert!(!allowed);
        assert!(s.tokens < 1.0);
        assert_eq!(s.last_check_ms, 0);
    }
}
