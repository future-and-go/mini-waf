# Phase 05 — Store Conformance Suite

**Priority:** P0 | **Status:** pending | **Depends:** 03
**Pattern reference:** `crates/waf-engine/src/device_fp/identity/conformance.rs`

## Goal

Single test suite parameterized over `dyn RateLimitStore` so memory + redis backends share identical contract verification.

## Requirements

- Public `run_conformance(store: Arc<dyn RateLimitStore>)` async fn
- Covers: Allow path, BurstExceeded path, SustainedExceeded path, window roll, key isolation, concurrent hammer
- Uses controlled `now_ms` (passed in, no real clock) so tests are deterministic
- Memory backend invokes the suite from its own test module
- Redis backend (phase 06) invokes suite from `#[cfg(feature = "redis-store")]` test gated on env var `REDIS_TEST_URL` (skip when absent — same as `device_fp` redis tests)

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/conformance.rs`

**Modify:**
- `crates/waf-engine/src/checks/rate_limit/mod.rs` — `#[cfg(any(test, feature = "test-conformance"))] pub mod conformance;`
- `crates/waf-engine/src/checks/rate_limit/store/memory.rs` — add `mod tests` calling conformance

## Test Cases (must include)

| # | Name | Config | Sequence | Expected |
|---|------|--------|----------|----------|
| 1 | basic_allow | cap=5, refill=1, win=60, lim=100 | 3 reqs | All Allow |
| 2 | burst_exceeded | cap=2, refill=0.1, win=60, lim=100 | 5 fast reqs | 2 Allow, 3 BurstExceeded |
| 3 | burst_refill | cap=1, refill=1, win=60, lim=100 | req @t=0, t=500, t=1100 | Allow, Burst, Allow |
| 4 | sustained_exceeded | cap=1000, refill=1000, win=10, lim=3 | 4 reqs | 3 Allow, 1 SustainedExceeded |
| 5 | window_roll | win=10, lim=2 | 2 reqs @t=0; 1 @t=11000 | All Allow |
| 6 | key_isolation | — | 100 reqs to key A; 1 to key B | B always Allow regardless of A's state |
| 7 | concurrent_hammer | cap=100, lim=1000 | spawn 200 tasks × 10 reqs each | total Allow ≈ allowed budget, no panics, no double-count |

## Verify

```bash
cargo test -p waf-engine rate_limit
cargo test -p waf-engine --features redis-store rate_limit  # redis backend (phase 06)
```

## Done When

- [ ] All 7 cases pass on `MemoryStore`
- [ ] Suite reusable: passes on `RedisStore` after phase 06 (this checkbox completed in phase 06)
- [ ] No flaky timing — tests use injected `now_ms`, not `Instant::now()`
