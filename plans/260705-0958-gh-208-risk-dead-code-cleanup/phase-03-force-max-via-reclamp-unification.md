---
phase: 3
title: "force_max via reclamp() unification"
status: completed
effort: "15m"
---

# Phase 3: force_max via reclamp() unification

## Overview

`MemoryRiskStore::force_max` hand-derives the clamped score instead of using the canonical
`RiskState::reclamp()`. Equivalent today, but drifts if clamp rules change. Unify the memory
backend to the same derivation used by `fold` and `apply_decay`. Redis `FORCE_MAX_SCRIPT`
parity duplication is intentional per the issue and stays untouched.

## Context

- Target: `crates/waf-engine/src/risk/store/memory.rs:181-188`. Current body inside the write
  guard:
  ```rust
  let mut state = state_ref.write();
  state.raw_score = 100;
  state.clamped_score = 100;
  state.pinned_until_ms = Some(until_ms);
  state.last_updated_ms = now_ms;
  ```
- Canonical derivation: `RiskState::reclamp()` (`state.rs:128-133`) sets
  `clamped_score = raw_score.clamp(0, 100) as u8`. Same callers of record:
  `score.rs:28`, `decay.rs:46`.
- Equivalence proof: `reclamp()` with `raw_score = 100` yields `clamped_score = 100`,
  identical to the manual assignment.

## Implementation Steps

1. Replace `state.clamped_score = 100;` with `state.reclamp();`, placed after
   `state.raw_score = 100;`. Final body:
   ```rust
   let mut state = state_ref.write();
   state.raw_score = 100;
   state.reclamp();
   state.pinned_until_ms = Some(until_ms);
   state.last_updated_ms = now_ms;
   ```
2. Do not touch `redis.rs` `FORCE_MAX_SCRIPT`.
3. No new test — existing cross-backend conformance already asserts the outcome (see below).

## Files

- Modify (owner): `crates/waf-engine/src/risk/store/memory.rs`

## Validation & Success Criteria

- [ ] `force_max` sets `clamped_score` via `reclamp()`; no manual `clamped_score = 100`.
- [ ] `cargo test -p waf-engine store::conformance` green — `conformance.rs:65` asserts
      `clamped_score == 100` and `:66` asserts the pin; `memory.rs:323`
      `force_max_sets_score_to_100` still passes.
- [ ] Redis parity: `REDIS_TEST_URL=... cargo test -p waf-engine conformance_redis` →
      `redis_force_max_pins_score` (`conformance_redis.rs:149`) green, confirming both backends
      agree after the change.

## Risks & Rollback

- Risk: `reclamp()` semantics differ from the manual set for `raw_score = 100`. None —
  `100.clamp(0,100) == 100`; conformance gate catches any divergence.
- Rollback: one-line revert.
