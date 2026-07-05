---
phase: 3
title: "Acceptance tests + quality gates"
status: pending
effort: "1.5h"
dependencies: [1, 2]
---

# Phase 3: Acceptance tests + quality gates

## Overview

Prove the issue's acceptance criterion end-to-end: a simulated Redis outage makes a
fail-open tier allow (with degraded telemetry) and a fail-closed tier block/
challenge. Default suite runs without a live Redis; a `REDIS_TEST_URL`-gated
variant exercises the real backend.

## Requirements

- Functional: one acceptance test drives the outage through the real enforcement
  surface — `Engine::inspect` if GH-196 has wired `RedisRiskStore` into it, else
  `Scorer::score` directly — asserting Open→Allow, Close→Block/Challenge.
- Non-functional: the default `cargo test -p waf-engine` run must not require a
  running Redis (mock store or unreachable URL).

## Architecture

- **Outage simulation without a live server**: prefer a mock `RiskStore` whose
  `apply` returns `ApplyResult { degraded: true, .. }` deterministically — no
  network, no flake. This is the primary acceptance test and exercises Phase 2's
  fail_mode branch precisely. (An unreachable-URL `RedisRiskStore` also produces
  `degraded: true`, but adds per-op timeout latency to the test.)
- **Test surface**:
  - If GH-196 landed the generic `Scorer<dyn RiskStore>` + engine wiring: build an
    `Engine` (or the scorer within it) over the mock store and call `inspect`, so
    the engine gate (`engine.rs:714`) is covered too.
  - Otherwise: construct `Scorer::new(mock_store, cfg)` directly and call `score`
    with a `RequestCtx` whose `tier_policy.fail_mode` is set per case. The scorer
    test already imports `TierPolicy`/`FailMode` (`scorer.rs:386,433`).
- **Cases** (table-driven):
  1. `FailMode::Open`, degraded, no cached score → `WafAction::Allow`, degraded
     `warn!` emitted (assert via score 0 + Allow; log capture optional).
  2. `FailMode::Open`, degraded, cached score ≥ block threshold →
     `Block`/`Challenge` per `decide` (proves cumulative score is *not* reset to 0).
  3. `FailMode::Close`, degraded, any score → `Block` (status 503).
  4. Control: healthy `apply` (`degraded: false`) → normal `decide` path unchanged.
- **Redis-gated variant** (`REDIS_TEST_URL`, gate pattern `redis.rs:585`): stand up
  a `RedisRiskStore`, seed a score, then point the connection at a dead port / drop
  the server (or use the unreachable-URL store) and assert the same Open/Close
  outcomes against the real error arms. Skips cleanly when the env var is unset.

## Related Code Files

- Add: acceptance test — colocate with the enforcement surface under test. If via
  the engine, extend `crates/waf-engine/src/engine.rs` risk tests (near
  `engine.rs:1399`) or the `tests/` acceptance suite; if via the scorer, extend
  `risk/scorer.rs` tests. Use a descriptive test name describing the behavior
  (e.g. `store_outage_fail_open_allows_fail_close_blocks`) — no plan/FR IDs.
- Read-only: Phase 1/2 changes.

## Implementation Steps

1. Add the mock `RiskStore` returning `degraded: true` (or reuse an extended
   `NoopStore`) in the test module.
2. Write the table-driven acceptance test covering the 4 cases above.
3. Add the `REDIS_TEST_URL`-gated real-outage variant.
4. Run gates:
   - `cargo test -p waf-engine risk` (no Redis) — green.
   - `REDIS_TEST_URL=redis://127.0.0.1:6379 cargo test -p waf-engine risk` — green
     where a server is available.
   - `cargo clippy -p waf-engine --all-targets` — clean.
   - `cargo test -p waf-engine` — no regression in existing risk/engine suites.

## Success Criteria

- [ ] Acceptance test present and green with **no** live Redis: Open→Allow,
      Close→Block/Challenge under simulated outage; cached-high-score Open case
      proves scores are not reset to 0.
- [ ] `REDIS_TEST_URL`-gated variant exercises the real store error arms and skips
      cleanly when unset.
- [ ] Full `cargo test -p waf-engine` + `cargo clippy -p waf-engine --all-targets`
      clean; no existing risk/engine test modified to pass (behavior preserved).

## Risk Assessment

- Risk: choosing the wrong enforcement surface if GH-196 ordering slips. Mitigation:
  the plan is `blockedBy` GH-196; if it has not landed, fall back to the direct
  `Scorer::score` surface (still fully validates the fail_mode mapping).
- Risk: real-Redis outage simulation is environment-sensitive (timeouts, ports).
  Mitigation: keep it behind `REDIS_TEST_URL`; the mock-store test is the
  authoritative, deterministic gate.

## Rollback

Tests are additive; revert the test file. No production rollback implication.
</content>
