---
phase: 2
title: "Remove unused Scorer ctors + migrate tests"
status: completed
effort: "20m"
---

# Phase 2: Remove unused Scorer ctors + migrate tests

## Overview

`Scorer::with_seed` (`scorer.rs:77`) and `Scorer::with_velocity_threshold`
(`scorer.rs:91`) are constructor duplicates of `new()` with zero production callers.
`with_seed` is redundant with `new()` + the existing `set_seed()` setter (`scorer.rs:104`).
`with_velocity_threshold` has no setter counterpart, but its only behavior (custom velocity
threshold) is exercised end-to-end by `tx_velocity_integration.rs:242` — so it is removed
outright with no setter added (YAGNI).

## Context

- Ctors to remove: `scorer.rs:76-101` (`with_seed`, `with_velocity_threshold`), including
  their `///` doc lines. Keep `new()` (:62-75) and `set_seed()` (:103-106).
- Test callers (only references): `crates/waf-engine/tests/risk_scorer_extended.rs`
  - `with_seed_constructor_and_set_seed` (:147-161) calls `Scorer::with_seed(...)` at :156
    then `scorer.set_seed(seed)`.
  - `with_velocity_threshold_constructor` (:164-176) calls
    `Scorer::with_velocity_threshold(store, swap, 1)` at :172.
- `VelocityLayer::new(threshold)` (`velocity/mod.rs:28`) stays — used by
  `VelocityLayer::with_defaults()` which `new()` already calls.

## Implementation Steps

1. Delete `with_seed` and `with_velocity_threshold` from the `impl<S: RiskStore> Scorer<S>`
   block (`scorer.rs:76-101`) and their doc comments. Do not alter `new()` or `set_seed()`.
   (Note: GH-196 Phase 1 relaxes this block's bound to `?Sized`; if GH-196 landed first,
   rebase onto the relaxed `impl` header.)
2. Migrate the seed test: in `with_seed_constructor_and_set_seed`, replace
   `let mut scorer = Scorer::with_seed(Arc::clone(&store), swap, Arc::clone(&seed));`
   with `let mut scorer = Scorer::new(Arc::clone(&store), swap);`. Keep the subsequent
   `scorer.set_seed(seed);` and the `score()` assertion. Rename the test to describe behavior
   without re-embedding a removed API name — e.g. `set_seed_then_score_allows`.
3. Delete the `with_velocity_threshold_constructor` test entirely (dead-ctor-only test;
   velocity behavior covered by `tx_velocity_integration.rs`).
4. Clean orphaned imports in the test file: if `SeedLayer` / `Arc::clone` usage changes,
   ensure no unused `use`. Verify `grep -rn "with_seed\b\|with_velocity_threshold" crates/`
   returns only the unrelated `XxHash64::with_seed` gateway-filter hits (3), no `Scorer::` hits.

## Files

- Modify (owner): `crates/waf-engine/src/risk/scorer.rs`
- Modify (owner): `crates/waf-engine/tests/risk_scorer_extended.rs`

## Success Criteria

- [ ] No `Scorer::with_seed` / `Scorer::with_velocity_threshold` references remain
      (`grep` shows only `XxHash64::with_seed` in gateway filters).
- [ ] `cargo test -p waf-engine --test risk_scorer_extended` green (migrated seed test passes).
- [ ] `cargo clippy -p waf-engine --all-targets -- -D warnings` clean.

## Risks & Rollback

- Risk: removing `with_velocity_threshold` drops the only scorer-level velocity-breach
  assertion. Mitigated — `tx_velocity_integration.rs:242` covers the pipeline path. If a
  scorer-unit assertion is later wanted, add it via `new()` (default threshold), not a
  restored ctor.
- Risk: soft overlap with GH-196 Phase 1 editing the same `impl` block. Mitigated — deletions
  are line-disjoint from the bound relaxation; rebase if GH-196 lands first.
- Rollback: revert the two-file diff.
