---
title: "GH-202: RiskBumpAction actor-keyed non-blocking risk submit"
description: "Fix three latent defects in RiskBumpAction: block_in_place panic on current_thread runtime, phantom-actor FpKey smuggling, severity flattened through BurstInterval weights"
status: pending
priority: P2
branch: "main-harness"
tags: [bug, ddos, risk-scoring, waf-engine]
blockedBy: []
blocks: []
created: "2026-07-05T00:42:35.741Z"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/202
---

# GH-202: RiskBumpAction actor-keyed non-blocking risk submit

## Overview

`crates/waf-engine/src/checks/ddos/action/risk.rs` (`RiskBumpAction`) has three
defects, all latent because `engine.rs:227-230` wires a ban-only
`CombinedAction` (`ban_and_risk` has no non-test callers):

1. **Runtime panic**: `execute()` bridges sync→async via
   `tokio::task::block_in_place(|| Handle::current().block_on(...))`
   (risk.rs:76-80). `block_in_place` panics on a `current_thread` runtime, and
   `crates/prx-waf/src/main.rs` builds `new_current_thread` runtimes.
   `ActionExecutor::execute` is sync on the request path (check.rs:165).
2. **Phantom actor**: client IP is smuggled as `FpKey { ja3: "ddos:{ip}" }`
   (risk.rs:36-43). The ingest worker (worker.rs:79-93) hashes it into
   `RiskKey { ip: None, fp_hash: hash(synthetic) }` — an actor the request-path
   scorer (keyed via `RiskKey::from_ip(ctx.client_ip)`, scorer.rs:270-278) can
   never join. DDoS bumps never affect the scored actor.
3. **Severity flattened**: the 0-100 risk delta is stuffed into
   `Signal::BurstInterval { count }` (risk.rs:46-51);
   signal_to_contributor.rs:119-125 flattens it to weight 20/30 via the
   `count >= 10` threshold (HardBurst 100 → 30).

## Solution Shape

Verified facts driving the design:

- `mpsc::Sender::try_send` is **sync** — no async bridge is needed at all.
  `ScoringAggregator::submit` already uses `try_send`; the `async fn` wrapper
  is the only thing forcing the panic-prone bridge.
- `MemoryRiskStore` is triple-indexed (by_ip / by_fp / by_session, memory.rs).
  A `RiskKey` with only the IP axis populated joins the request-path actor via
  `by_ip` — `RiskKey` already has a first-class IP axis.
- `Signal` is a flat exhaustive enum; only two match sites exist
  (`signal.rs::name()`, `signal_to_contributor.rs`). Only 3 `RiskAggregator`
  impls exist, all in-crate (Noop, Logging, Scoring).
- `IpAddr` is std, so an IP-keyed trait method keeps `device_fp`
  scoring-agnostic (its documented contract).

Fix, one phase per defect axis:

1. Add sync, IP-keyed `RiskAggregator::submit_ip(&self, ip, &[Signal])`;
   extend ingest `Job` with an `actor_ip` axis; worker builds
   `RiskKey { ip: actor_ip, fp_hash, .. }`.
2. Add `Signal::DdosBurst { risk_delta: u8 }` (delta passthrough in
   signal_to_contributor — no weight-table flattening); rewrite
   `RiskBumpAction::execute` to `submit_ip` with that signal; delete the
   FpKey-smuggling and block_in_place code.
3. Integration test proving HardBurst raises the scored actor's state on the
   real `RiskKey` IP axis; current_thread no-panic regression; full gates.

## Non-Goals

- Wiring `RiskBumpAction` into `engine.rs` (`ban_and_risk`). Issue scope is
  "safe and correct **before** it is ever wired". Wiring needs the engine's
  scorer store shared with a `ScoringAggregator` — follow-up work.
- Executing actions on `DetectorVerdict::SoftAnomaly` in check.rs (currently
  log-only; behavior change out of scope).
- Redis risk store changes — key shape is unchanged.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Actor-Keyed Sync Submit Seam](./phase-01-actor-keyed-sync-submit-seam.md) | Pending |
| 2 | [DdosBurst Signal + RiskBumpAction Rewrite](./phase-02-ddosburst-signal-riskbumpaction-rewrite.md) | Pending |
| 3 | [Integration Tests & Verification](./phase-03-integration-tests-verification.md) | Pending |

## Acceptance Criteria (from GH-202)

- [ ] No `block_in_place`/`block_on`: fire-and-forget submit that is
      runtime-flavor agnostic.
- [ ] DDoS risk deltas land on the actor's real `RiskKey` (IP axis); test:
      HardBurst raises the scored actor's state.
- [ ] Severity preserved end-to-end (dedicated signal carrying the delta).

## Intake

- Lane: normal (flags: existing-behavior on shared trait seam, weak-proof —
  current tests assert the buggy behavior). No hard gates.
- `scripts/bin/harness-cli` not present in repo — intake row skip.

## Dependencies

- None. Related merged work: GH-195 (risk verdict enforcement, #211), GH-198
  (redis RiskState round-trip, #210) — no file overlap with this plan's
  target files except shared test suites.
