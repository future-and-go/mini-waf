---
phase: 2
title: "Conformance Test Coverage"
status: pending
effort: "S"
priority: P1
dependencies: [1]
---

# Phase 2: Conformance Test Coverage

## Overview

Add a shared conformance case that forces the decay path so the Lua-created
decay contributor's round-trip is proven on both backends (memory + Redis).
`is_new` and empty-contributors already have assertions
(conformance.rs:34/51, conformance_redis.rs:72/77) — they need no new tests,
only a live Redis to run against (phase 3).

## Requirements

- Functional: one new `pub async fn test_decay_contributor_roundtrip<S: RiskStore>`
  in the shared suite, wired into `run_all`, exercised by both the memory
  conformance test and the Redis-gated tests.
- Non-functional: deterministic (driven by explicit `now_ms` values, no
  wall-clock); follows existing conformance test style.

## Architecture

Decay triggers inside `store.apply` when: prior state exists,
`clean_streak >= MIN_CLEAN_STREAK`, not pinned, and `raw_score > MAX_DECAY`
(50). Empty-deltas applies increment `clean_streak`. So the recipe is:

1. `apply(key, [contributor(+90)], t0)` → raw_score 90, streak 0.
2. `MIN_CLEAN_STREAK` × `apply(key, [], t_n)` → streak reaches threshold.
3. One more `apply(key, [], t_final)` → decay fires: score drops by
   `DECAY_RATE`, a `Decay` contributor is appended by the backend.
4. Assert: returned state parses (implicit via typed `ApplyResult`), score
   decreased, `state.contributors` contains `ContributorKind::Decay`.
5. `read(key)` → parses and matches; this is the assertion that fails today
   on Redis with `{"Decay":null}` persisted.

Use `crate::risk::decay::{MIN_CLEAN_STREAK, DECAY_RATE, MAX_DECAY}` constants
rather than literals so the test tracks config drift.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/store/conformance.rs`
  (new case + `run_all` registration)
- Modify: `crates/waf-engine/src/risk/tests/conformance_redis.rs`
  (only if it enumerates cases individually; `redis_store_passes_conformance`
  calls `run_all` and picks the new case up automatically)

## Implementation Steps

1. Write `test_decay_contributor_roundtrip` per the recipe above, resetting
   with `store.reset_all()` first (existing suite convention).
2. Register it in `conformance::run_all` (conformance.rs:19-25).
3. Run memory-backend suite locally:
   `cargo test -p waf-engine --lib -- risk::store::conformance` — must pass
   (proves the recipe + parity target before Redis ever runs it).
4. If a local `REDIS_TEST_URL` is available, run the Redis-gated suite; if not
   (default in this sandbox: no docker, no Redis), defer to phase 3 CI run and
   state so in the implementation report.

## Success Criteria

- [ ] New conformance case registered in `run_all` and passing on memory backend
- [ ] Case asserts: post-decay apply parses, score decreased by `DECAY_RATE`,
      `Decay` contributor present, and subsequent `read` round-trips
- [ ] On live Redis (CI): case fails on pre-phase-1 script, passes after
      (regression lock for the `{"Decay":null}` bug)

## Risk Assessment

- **Flaky-clock risk:** none — all timestamps are explicit `now_ms` arguments.
- **Threshold drift:** decay thresholds are constants today; if they become
  config, the test's use of the exported constants keeps it honest.
- **Memory-backend divergence:** if memory store's decay recipe differs (e.g.
  streak counted differently), the test surfaces it as a parity failure —
  that is signal, not noise; reconcile against decay.rs as source of truth.
