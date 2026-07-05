---
phase: 1
title: "Enforce per-request delta cap in the scoring pipeline"
status: pending
effort: 1h
---

# Phase 1: Enforce per-request delta cap in the scoring pipeline

## Overview

Wire the defined-but-unused `clamp_per_request_deltas` into the two `store.apply`
choke points so a single request (or async ingest job) cannot add more than
`MAX_PER_REQUEST_DELTA = 100` positive raw score. Negative deltas (credits) are
preserved. Both memory and redis backends are covered because both are reached
through the same `store.apply` calls.

## Verified Context

- Helper: `clamp_per_request_deltas(&[Contributor]) -> (Vec<Contributor>, i32)`
  (`crates/waf-engine/src/risk/score.rs:68`) — caps positive-delta sum to 100 by
  truncating oldest positives, keeps all negatives, returns pre-clamp `raw_sum`.
  Re-exported at `risk/mod.rs:46`. Zero non-test call sites today.
- Sync choke point: `Scorer::score_with_l2` builds `all_deltas` (input + anomaly +
  velocity + challenge-credit) then `let result = self.store.apply(&key, &all_deltas, now_ms)`
  (`crates/waf-engine/src/risk/scorer.rs:233-255`). The seed short-circuit path
  (`scorer.rs:172`) re-enters through `score_with_l2`, so this is the single union point.
- Async choke point: `ingest/worker.rs:106` `store.apply(&risk_key, &contributors, now_ms)`
  — one job = one request's fingerprint signals.
- Canary path (`scorer.rs:182-206`) uses `force_max` → `store.force_max`, no `fold`.
  Not a delta path — must stay uncapped. Do NOT touch it.

## Implementation Steps

1. In `score_with_l2` (`scorer.rs`), immediately before the `store.apply` call, clamp:
   ```rust
   let (all_deltas, _raw_sum) = clamp_per_request_deltas(&all_deltas);
   let result = self.store.apply(&key, &all_deltas, now_ms).await?;
   ```
   Import `clamp_per_request_deltas` from `crate::risk::score`. Discard `raw_sum`.
2. In `ingest/worker.rs`, before its `store.apply`, clamp `contributors` the same way
   (`let (contributors, _) = clamp_per_request_deltas(&contributors);`). Keep the
   existing empty-guard ordering (the empty check at `worker.rs:98` stays; clamping a
   non-empty batch never empties it because negatives are preserved and at least the
   newest positive fits).
3. Do not alter `fold` (`score.rs:13`) or the Lua fold — the per-request cap is
   additive, not a replacement for the total-score clamp.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/scorer.rs` (one clamp line in `score_with_l2`)
- Modify: `crates/waf-engine/src/risk/ingest/worker.rs` (one clamp line before apply)

## Success Criteria

- [ ] `Scorer` unit test: an oversized positive batch (sum > 100) yields
      `result.score == 100` and preserves any negative credit in the batch.
- [ ] Canary/force_max behavior unchanged (existing scorer canary test still green).
- [ ] `cargo test -p waf-engine risk` green.

## Risk Assessment

- Likelihood low / impact low. The helper is already unit-tested; wiring is two lines.
- Edge: a batch of only negatives — `clamp_per_request_deltas` returns it unchanged
  (positive_sum 0 ≤ 100). Verified by `clamp_preserves_negative_deltas` test in score.rs.

## Rollback

Revert the two clamp lines; behavior returns to uncapped. No data/schema impact.
</content>
