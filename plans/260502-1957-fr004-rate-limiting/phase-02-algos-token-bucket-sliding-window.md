# Phase 02 — Algorithms: Token Bucket + Sliding Window Counter

**Priority:** P0 | **Status:** done | **Depends:** 01

## Goal

Pure-logic algos, backend-agnostic. No I/O, no DashMap, no Redis — just structs + functions on `&mut State`. Heavily unit-tested.

## Requirements

- `TokenBucketState { tokens: f64, last_check_ms: i64 }` — 16 bytes
- `SlidingWindowState { curr_count: u32, prev_count: u32, curr_window_start_ms: i64 }` — 16 bytes
- Pure functions: take `&mut State`, `&LimitCfg`, `now_ms` → return `bool` (allowed)
- Saturating arithmetic; clamp `tokens` to `[0, capacity]`
- 100% branch coverage in unit tests

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/algo/token_bucket.rs`
- `crates/waf-engine/src/checks/rate_limit/algo/sliding_window.rs`

**Modify:**
- `crates/waf-engine/src/checks/rate_limit/algo/mod.rs` — pub use both

## Implementation

### `token_bucket.rs`

```rust
use crate::checks::rate_limit::LimitCfg;

#[derive(Clone, Copy, Debug)]
pub struct TokenBucketState {
    pub tokens: f64,
    pub last_check_ms: i64,
}

impl TokenBucketState {
    pub fn new_full(cfg: &LimitCfg, now_ms: i64) -> Self {
        Self { tokens: cfg.burst_capacity as f64, last_check_ms: now_ms }
    }

    /// Returns true when consumption succeeded.
    pub fn try_consume(&mut self, cfg: &LimitCfg, now_ms: i64) -> bool {
        let elapsed_s = ((now_ms - self.last_check_ms).max(0) as f64) / 1000.0;
        let refill = elapsed_s * cfg.burst_refill_per_s;
        self.tokens = (self.tokens + refill).min(cfg.burst_capacity as f64);
        self.last_check_ms = now_ms;
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}
```

### `sliding_window.rs`

```rust
use crate::checks::rate_limit::LimitCfg;

#[derive(Clone, Copy, Debug)]
pub struct SlidingWindowState {
    pub curr_count: u32,
    pub prev_count: u32,
    pub curr_window_start_ms: i64,
}

impl SlidingWindowState {
    pub fn new(now_ms: i64, window_secs: u32) -> Self {
        let win_ms = window_secs as i64 * 1000;
        Self {
            curr_count: 0,
            prev_count: 0,
            curr_window_start_ms: (now_ms / win_ms) * win_ms,
        }
    }

    /// Roll window if past boundary; estimate weighted count; allow if under limit.
    pub fn try_consume(&mut self, cfg: &LimitCfg, now_ms: i64) -> bool {
        let win_ms = cfg.window_secs as i64 * 1000;
        let bucket_now = (now_ms / win_ms) * win_ms;
        let advance = ((bucket_now - self.curr_window_start_ms) / win_ms).max(0);
        match advance {
            0 => {}
            1 => {
                self.prev_count = self.curr_count;
                self.curr_count = 0;
                self.curr_window_start_ms = bucket_now;
            }
            _ => {
                self.prev_count = 0;
                self.curr_count = 0;
                self.curr_window_start_ms = bucket_now;
            }
        }
        let elapsed_in_curr = (now_ms - self.curr_window_start_ms) as f64;
        let weight_prev = 1.0 - (elapsed_in_curr / win_ms as f64).clamp(0.0, 1.0);
        let estimated = self.curr_count as f64 + (self.prev_count as f64 * weight_prev);
        if (estimated + 1.0) > cfg.window_limit as f64 {
            false
        } else {
            self.curr_count = self.curr_count.saturating_add(1);
            true
        }
    }
}
```

## Tests (must include)

- TB: empty bucket rejects; full bucket allows N; refill across time advances correctly; saturates at capacity
- TB: clock-skew negative `now_ms` does not panic / inflate
- SW: under-limit allows; over-limit blocks; window roll resets correctly; multi-window-skip clears prev
- SW: at window boundary the interpolation degrades smoothly (weight=0 at end of window)

## Verify

```bash
cargo test -p waf-engine rate_limit::algo
cargo clippy -p waf-engine -- -D warnings
```

## Done When

- [x] Both algos compile, all unit tests pass
- [x] No `.unwrap()` outside `#[cfg(test)]`
- [ ] Branch coverage ≥95% on algo files (checked via `cargo llvm-cov` if configured)
