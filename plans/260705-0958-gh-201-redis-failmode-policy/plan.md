---
title: "GH-201 redis risk store: propagate errors, honor TierPolicy fail_mode on outage"
description: "Redis store stops silently faking score-0 on outage; apply signals an explicit degraded flag, the Scorer maps store failure to the tier's FailMode (Open → allow with degraded telemetry, Close → block/challenge)."
status: pending
priority: P2
branch: "main-harness"
tags: [bug, area:engine, risk, redis, security, gh-201]
blockedBy: [260705-0953-gh-196-risk-admin-api-engine-wiring]
blocks: []
created: "2026-07-05T03:02:55.492Z"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/201
---

# GH-201 redis risk store: propagate errors, honor TierPolicy fail_mode on outage

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/201 (P2 bug, CONFIRMED by
multi-agent review 2026-07-03; all claims re-verified on HEAD `9ee484b`, 2026-07-05
— issue line numbers predate the GH-206 #209 single-RTT rework and are stale).

`RedisRiskStore` hardcodes fail-open on every error: during a Redis outage an
actor's cumulative score silently resets to 0, disabling cluster-wide scoring with
only a `warn!`, and a `FailMode::Close` tier still fails open. The tier's declared
`fail_mode` is consulted **only** on the DDoS path, never on the risk path.

Verified failure chain on HEAD:

1. **Store fabricates fresh state on failure.** `RedisRiskStore::apply` swallows
   all three failure modes and returns `Ok`: apply error
   (`crates/waf-engine/src/risk/store/redis.rs:360-370`), timeout (`redis.rs:371-381`),
   each falling back to the LRU cache or `RiskState::new(now_ms)` — score 0,
   `is_new = true`. `read` does the same (`redis.rs:313-316`). The caller cannot
   tell a real score-0 from an outage.
2. **Scorer never sees a failure.** `score_with_l2` does
   `self.store.apply(...).await?` (`risk/scorer.rs:255`) then gates purely on
   `ctx.tier_policy.risk_thresholds` (`scorer.rs:259`). Because `apply` never
   returns `Err`, the `?` is dead for outages and `fail_mode` is never read.
3. **Engine swallows scorer `Err` too.** `inspect()` calls the scorer under
   `if let Ok(scorer_result) = self.scorer.score(...).await` (`engine.rs:705`);
   a returned `Err` is silently dropped and risk enforcement is skipped — a second
   fail-open layer. **Consequence:** simply propagating `Err` up is not enough;
   the Scorer must translate store failure into a `ScorerResult` action, mirroring
   how the DDoS path turns `degrade::resolve` into a `DegradeAction`
   (`checks/ddos/check.rs:91`, `checks/ddos/degrade.rs:55`).
4. **`fail_mode` already exists and is the right knob.** `TierPolicy.fail_mode:
   FailMode { Open, Close }` (`crates/waf-common/src/tier.rs:31,73`); DDoS uses
   `FailMode::Close` ⇒ always block (`degrade.rs:57`). Risk needs the same mapping.

Established repo pattern to follow: a small pure `resolve`-style mapping
`(FailMode, …) → action`, unit-tested exhaustively, consumed at the call site
(`checks/ddos/degrade.rs`).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Store faithful failure signaling (degraded ApplyResult + faithful Err)](./phase-01-store-faithful-failure-signaling-degraded-applyresult-faithf.md) | Pending |
| 2 | [Scorer honors TierPolicy fail_mode on store failure](./phase-02-scorer-honors-tierpolicy-fail-mode-on-store-failure.md) | Pending |
| 3 | [Acceptance tests + quality gates](./phase-03-acceptance-tests-quality-gates.md) | Pending |

## Key Decisions

- **Explicit degraded indicator on the enforcement path, faithful `Err` on the
  advisory paths.** `apply` is the hot enforcement call; giving it an explicit
  `ApplyResult.degraded: bool` (the issue's "or an explicit degraded indicator"
  option) is cleaner than `Err` because the Scorer must produce a *decision*, not
  bubble an error the engine already swallows (`engine.rs:705`). `read` and
  `force_max` are advisory (not on the enforcement gate) — they return `Err`
  faithfully, dropping the silent cache substitution (`read`, `redis.rs:313-316`).
  `force_max` already returns `Err` on failure (`redis.rs:422-429`) — no change.
- **Keep the LRU cache, but as an *explicit* degraded-mode datum, not a silent
  mask.** On Redis failure `apply` returns `Ok(ApplyResult { degraded: true, state
  })` where `state` is the LRU cache hit if present, else `RiskState::new(now_ms)`
  (score 0). The bug was that this branch was *invisible* to the caller; the
  `degraded` flag makes it a policy input. This avoids removing `cache_capacity`
  from the public `RedisRiskConfig` (which GH-196 wires through
  `to_runtime_config`) and preserves the cache's defensive value on Open tiers.
  Rejected alternative: delete the cache entirely (smaller surface, but discards
  last-known score and churns `RedisRiskConfig` + GH-196's config mapping). See
  Open Questions.
- **Scorer owns the fail_mode mapping via a pure helper.** Add
  `fn degraded_action(fail_mode, score, thresholds, override_block) -> WafAction`
  in the risk module, mirroring `degrade::resolve`:
  - `FailMode::Open` → `decide(score, thresholds, override_block)` — trust the
    best-known score (cache hit → real defense; no cache → 0 → Allow). This is
    what fixes "score resets to 0 disables scoring" for Open tiers.
  - `FailMode::Close` → `WafAction::Block { status: 503 }` — never trust a stale/
    absent score; parity with DDoS `Close ⇒ Block 503`.
  The Scorer branches on `result.degraded`; when `false` the existing
  `decide(...)` path (`scorer.rs:260`) is unchanged (zero hot-path cost when Redis
  is healthy / for the memory backend).
- **Circuit breaker becomes a real fast-fail (recommended, small).** At the top of
  `apply`, if `breaker_open()` (`redis.rs:122`) short-circuit to the degraded path
  without issuing the RTT — turning today's telemetry-only counter into an outage
  fast-path and avoiding timeout pile-up. Correctness does not depend on it; the
  degraded flag is the fix. Left as an implementation option in Phase 1.
- **Degraded telemetry, no new metrics subsystem.** There is no `RiskMetrics`
  struct (only `DdosMetrics`). Emit a `warn!(target: "risk::degrade", …)` on the
  degraded branch (mirrors the `ddos::audit` warn convention). A counter is YAGNI
  unless a risk metrics struct already lands via another plan.
- **Risk-disabled / empty-key fast paths untouched.** `fail_mode` only engages on
  the real scoring path: `score()` still early-returns Allow/score-0 when
  `!cfg.enabled` (`scorer.rs:148`) and when the key is empty (`scorer.rs:224`);
  `inspect_pipeline` `FastPath` exits still skip scoring. No outage policy runs
  when risk is off — same as today.

## Cross-Plan Dependencies

- **blockedBy GH-196** (`plans/260705-0953-gh-196-risk-admin-api-engine-wiring`) —
  soft ordering, land GH-196 first. Two reasons: (a) GH-196 Phase 1 relaxes
  `Scorer<S: RiskStore + ?Sized>` and wires `RedisRiskStore` into the production
  `inspect()` path, so GH-201's acceptance tests have a reachable production Redis
  path to exercise; (b) GH-196 Phase 1 also constructs the store from
  `StoreConfig` via `to_runtime_config`, the same `RedisRiskConfig` this plan
  chooses not to reshape. Textual overlap in `store/redis.rs` is confined to the
  `apply`/`read` error arms vs GH-196's untouched construction path — low conflict,
  but ordering removes the merge risk.
- **No conflict with GH-202** (`260705-0739-gh-202-riskbump-actor-keyed-submit`):
  that plan touches `checks/ddos/action/risk.rs` + the aggregator, not the store
  error arms or the scorer gate.

## Acceptance Criteria (from issue)

- [ ] Store errors surface as an explicit degraded indicator (`apply`) or faithful
      `Err` (`read`) — no silent score-0 substitution [Phase 1].
- [ ] Scorer applies `TierPolicy.fail_mode` on store failure; `FailMode::Close`
      blocks/challenges, `FailMode::Open` allows on best-known score [Phase 2].
- [ ] Test: simulated Redis outage → fail-open tier allows (degraded telemetry),
      fail-closed tier does not [Phase 3].

## Validation

- `cargo test -p waf-engine risk` green (store degraded-flag unit tests, scorer
  fail_mode branch tests, engine outage acceptance test).
- Redis-gated variant (`REDIS_TEST_URL`) for the real-redis outage path; the
  default suite uses a mock `RiskStore` / unreachable-URL store so it runs without
  a live Redis.
- `cargo clippy -p waf-engine --all-targets` clean.

## Open Questions

- LRU cache: keep-as-explicit-degraded (recommended, this plan) vs delete-entirely?
  Deletion is simpler and more honest ("we don't know the score") but loses the
  last-known-score defense on Open tiers and reshapes public `RedisRiskConfig`.
  Reviewer to confirm before Phase 1.
- `FailMode::Close` degraded action: `Block { status: 503 }` (parity with DDoS
  degrade) vs `Challenge` (softer, lets legitimate users solve during the outage).
  Plan recommends `Block 503`; a product call may prefer `Challenge`.
</content>
</invoke>
