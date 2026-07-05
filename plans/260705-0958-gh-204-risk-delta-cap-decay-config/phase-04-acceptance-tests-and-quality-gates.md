---
phase: 4
title: "Acceptance tests and quality gates"
status: completed
effort: 1h
---

# Phase 4: Acceptance tests and quality gates

## Overview

Prove the three fixes bind, on both backends where applicable, and run workspace
quality gates. Redis assertions are `REDIS_TEST_URL`-gated (skip cleanly when unset),
matching the existing pattern in `store/redis.rs:585` and `risk/tests/conformance_redis.rs`.

## Test Matrix

| Behavior | Memory | Redis (gated) | Location |
| --- | --- | --- | --- |
| Oversized positive batch capped to +100 | unit | conformance | scorer test + `store/conformance.rs` |
| Negative credit preserved through cap | unit | — | scorer/score test |
| Decay honors configured `decay_rate` (e.g. 3/req) | unit | conformance | decay/lifecycle + redis conformance |
| `decay_rate: 0` disables decay entirely | unit | conformance | decay + redis conformance |
| `validate()` rejects bad configs | unit | — | `config.rs` tests |
| Canary/force_max stays uncapped | unit | — | existing scorer canary test (regression) |

## Implementation Steps

1. **Delta cap (Phase 1):** add a scorer test that applies deltas summing > 100
   positive (plus a negative credit) and asserts `result.score == 100` and the credit
   survived. Add the same case to `store/conformance.rs::run_all` so both backends run
   it (memory always, redis under `REDIS_TEST_URL`).
2. **Decay honors config (Phase 2):** parameterize the decay conformance case
   (`store/conformance.rs:174`) to build the store with a non-default `DecayConfig`
   (`decay_rate: 3`) and assert score drops by 3 per clean request past
   `min_clean_streak`. Add a `decay_rate: 0` case asserting the score is unchanged
   after many clean requests. Memory via `MemoryRiskStore::with_decay`; redis via
   `RedisRiskConfig { decay, .. }`.
3. **validate() (Phase 3):** unit tests in `config.rs` for each reject case and the
   accept cases (default, `decay_rate: 0`, `min_clean_streak: 0`), plus a `from_path`
   test that a `gc_interval_secs: 0` YAML returns `Err` without panicking.
4. **Quality gates:**
   - `cargo test -p waf-engine risk`
   - `cargo test -p waf-engine --features redis-store` (with and without `REDIS_TEST_URL`)
   - `cargo clippy --workspace --all-targets`
   - `cargo build -p prx-waf` (engine store-construction change compiles end-to-end)

## Related Code Files

- Modify: `crates/waf-engine/src/risk/scorer.rs` (test module)
- Modify: `crates/waf-engine/src/risk/store/conformance.rs` (cap + decay-rate cases)
- Modify: `crates/waf-engine/src/risk/config.rs` (validate test module)
- Possibly: `crates/waf-engine/src/risk/tests/conformance_redis.rs` (invoke new cases)

## Success Criteria

- [ ] All four acceptance criteria in `plan.md` have a green test.
- [ ] Redis-gated cases run when `REDIS_TEST_URL` is set and skip (not fail) otherwise.
- [ ] `cargo clippy --workspace --all-targets` clean; workspace tests green.

## Risk Assessment

- Likelihood low / impact low. Test-only phase.
- Watch: reusing `conformance.rs` cases across backends means memory + redis share
  assertions — keep decay expectations tolerant of the "decay runs BEFORE fold, so it
  sees streak-1" timing already documented at `store/conformance.rs:184-190`.

## Rollback

Remove added tests. No production impact.
</content>
