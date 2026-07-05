---
phase: 2
title: "Scorer honors TierPolicy fail_mode on store failure"
status: pending
effort: "2h"
dependencies: [1]
---

# Phase 2: Scorer honors TierPolicy fail_mode on store failure

## Overview

Teach the Scorer to act on the `degraded` signal from Phase 1 using the request's
`TierPolicy.fail_mode`. A small pure helper maps `(FailMode, score, thresholds)` to
a `WafAction`, mirroring `checks/ddos/degrade::resolve`. The Scorer keeps returning
`Ok(ScorerResult)` so the engine's `if let Ok(...)` gate (`engine.rs:705`) enforces
the fail-closed decision instead of swallowing it.

## Requirements

- Functional: when `apply` reports `degraded: true`, the action is chosen by
  `ctx.tier_policy.fail_mode` — `Open` ⇒ decide on best-known score, `Close` ⇒
  Block. When `degraded: false`, behavior is byte-for-byte the current
  `decide(...)` path.
- Non-functional: no extra `.await`, no extra allocation on the healthy path; the
  branch is a single bool check after the existing `apply`.

## Architecture

- **New pure helper** `degraded_action(fail_mode: FailMode, score: u8, thresholds:
  &RiskThresholds, override_block: bool) -> WafAction`. Place it next to `decide`
  in `crates/waf-engine/src/risk/threshold.rs` (keeps the risk decision vocabulary
  in one module; `decide` is at `threshold.rs:17`). Logic:
  - `FailMode::Open` → `decide(score, thresholds, override_block)` (trusts the
    best-known score: cache hit defends, absent → 0 → Allow).
  - `FailMode::Close` → `WafAction::Block { status: 503, body: None }` (parity with
    DDoS `Close ⇒ Block 503`, `degrade.rs:57`). See plan Open Questions re Challenge.
  - Pure, no I/O, no panic — unit-testable as an exhaustive 2×band table like
    `degrade.rs`'s `RESOLVE_TABLE`.
- **Scorer wiring** in `score_with_l2` (`risk/scorer.rs:254-266`):
  - keep `let result = self.store.apply(&key, &all_deltas, now_ms).await?;`
    (`scorer.rs:255`) — a true `Err` still propagates, but Phase 1 makes the
    outage path return `Ok(degraded)` not `Err`.
  - replace the action computation (`scorer.rs:258-260`) with:
    ```
    let override_block = state.is_pinned(now_ms);
    let thresholds = &ctx.tier_policy.risk_thresholds;
    let action = if result.degraded {
        warn!(target: "risk::degrade", client_ip = %ctx.client_ip,
              fail_mode = ?ctx.tier_policy.fail_mode,
              "risk store degraded; applying tier fail_mode");
        degraded_action(ctx.tier_policy.fail_mode, state.clamped_score,
                        thresholds, override_block)
    } else {
        decide(state.clamped_score, thresholds, override_block)
    };
    ```
  - `ScorerResult { action, score: state.clamped_score, is_new: result.is_new }`
    unchanged otherwise.
- **Imports**: add `FailMode` (already used in scorer tests, `scorer.rs:386`) and
  `warn` to the scorer's `use` block; `degraded_action` from `crate::risk::threshold`.
- **No engine change required.** The gate at `engine.rs:714-716` already escalates a
  scorer `Block`/`Challenge` when the pipeline decision is a plain Allow, and
  `make_risk_decision` (`engine.rs:735-757`) already renders `Block { status }`.
  A `Close`-tier degraded Block therefore flows through unchanged. Confirm the
  503 status renders acceptably via `make_risk_decision`'s `render_block_page`.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/threshold.rs` (add `degraded_action` + tests).
- Modify: `crates/waf-engine/src/risk/scorer.rs` (branch on `result.degraded`,
  imports, `warn!`).
- Read-only: `crates/waf-engine/src/engine.rs` (verify gate/`make_risk_decision`).
- Read-only: `crates/waf-common/src/tier.rs` (`FailMode`, `RiskThresholds`).

## Implementation Steps

1. Add `degraded_action` to `threshold.rs` with a rustdoc matrix; unit-test both
   `FailMode` arms across allow/challenge/block score bands and the pinned override.
2. Wire the `result.degraded` branch into `score_with_l2`; add imports + `warn!`.
3. Scorer unit tests using a mock `RiskStore` whose `apply` returns `degraded:
   true` (define a small in-test store, or extend `NoopStore`): assert Open tier →
   Allow at score 0 / Block at cached high score, Close tier → Block.
4. `cargo test -p waf-engine risk::scorer risk::threshold` green.

## Success Criteria

- [ ] `degraded_action` exists, pure, exhaustively unit-tested (both fail modes ×
      score bands + pinned override).
- [ ] Scorer test: mock store `degraded: true` + `FailMode::Open` low score →
      `Allow`; + high cached score → `Block`/`Challenge`; + `FailMode::Close` →
      `Block` regardless of score.
- [ ] Healthy path (`degraded: false`) unit test unchanged — still routes through
      `decide`.
- [ ] `cargo clippy -p waf-engine --all-targets` clean.

## Risk Assessment

- Risk: the engine gate only escalates when the pipeline decision is a plain Allow
  (`engine.rs:714`). A `Close`-tier outage on a request that *already* carries a
  detection keeps that detection's decision — acceptable (still enforced), document
  in a test comment (as behavior, not a plan ID).
- Risk: `warn!` on every degraded request could flood logs during a long outage.
  Mitigation: it fires only while degraded (bounded by outage duration); rate
  limiting is YAGNI unless observed. The breaker short-circuit (Phase 1) already
  caps the redis-call rate.

## Rollback

Revert the `score_with_l2` branch to the single `decide(...)` call and drop
`degraded_action`. Phase 1's `degraded` flag becomes inert (ignored) — safe,
restores prior fail-open without touching the store layer.
</content>
