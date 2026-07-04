---
title: "GH-198 Redis risk store: RiskState round-trip + is_new fixes, CI Redis coverage"
description: "Fix APPLY_SCRIPT is_new (Redis Lua GET returns false, not nil) and Decay contributor kind serialization; add decay round-trip conformance case; run Redis-gated tests in CI via Valkey service container."
status: in-progress
priority: P1
branch: "main-harness"
tags: [bug, area:engine, risk-store, redis, gh-198]
blockedBy: []
blocks: []
created: "2026-07-04T16:12:19.781Z"
createdBy: "ck:plan"
source: skill
---

# GH-198 Redis risk store: RiskState round-trip + is_new fixes, CI Redis coverage

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/198 (p1 bug, CONFIRMED).

`APPLY_SCRIPT` in `crates/waf-engine/src/risk/store/redis_lua.rs` has two live
correctness bugs (verified on HEAD c37a8fe, 2026-07-04):

1. **`is_new` always false** — line 120: `local is_new = (state_json == nil)`.
   Redis Lua `GET` on a missing key returns boolean `false`, never `nil`, so the
   comparison is always false. Diverges from `MemoryRiskStore` (memory.rs:139-164).
   Side effect: the "skip decay for new state" guard (`if not is_new and ...`,
   line 123) never short-circuits (benign today — fresh state has
   `clean_streak = 0` — but semantically wrong).
   Fix (validation session 1): compute `is_new = (#candidates == 0)` at owner
   resolution — mint-path semantics, exact memory-store parity — rather than
   from state-key existence.
2. **Decay contributor unparseable** — line 137: the Lua-created decay
   contributor uses `kind = {Decay = cjson.null}`, which encodes as
   `{"Decay":null}`. `ContributorKind` (state.rs:38) is an externally-tagged
   serde enum; the `Decay` unit variant must be the JSON string `"Decay"`
   (parity target: decay.rs:45 `Contributor::new(ContributorKind::Decay, ...)`).
   Once a decay contributor is persisted, the state key is unparseable: the
   apply-response parse at redis.rs:352-353 errors via `?` (bypassing the cache
   fallback) and every later `read_state` (redis.rs:257) fails until TTL expiry
   — risk scoring silently degrades for that actor.

Issue criterion "empty contributors encodes as `[]`" was **already fixed by
PR #209** (`fix_empty_contributors` gsub patch, both scripts); it stays covered
by existing conformance cases once they actually run in CI.

3. **CI gap** — `.github/workflows/ci.yml` test job runs
   `cargo test --workspace --all-features` with no Redis service, so every
   `REDIS_TEST_URL`-gated test early-returns as pass. The three known failures
   (`risk::store::redis::tests::basic_apply_and_read`,
   `risk::tests::conformance_redis::redis_apply_accumulates_score`,
   `risk::tests::conformance_redis::redis_store_passes_conformance`) only
   reproduce against a live Redis/Valkey.

**Intake lane:** normal (flags: existing behavior, weak proof). No schema, no
auth, no public contract change. `is_new` consumers: `ApplyResult.is_new` →
`ScorerResult.is_new` (informational; no enforcement decision keys off it).

**Environment note:** local sandbox has no docker socket and no local Redis;
Redis-gated verification must go through CI (phase 3) or an operator-provided
`REDIS_TEST_URL`. Phase ordering intentionally lands CI wiring in the same PR
so the fix is proven by the pipeline.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Lua Script Fixes](./phase-01-lua-script-fixes.md) | Implemented — CI proof pending |
| 2 | [Conformance Test Coverage](./phase-02-conformance-test-coverage.md) | Implemented — CI proof pending |
| 3 | [CI Redis Service](./phase-03-ci-redis-service.md) | Implemented — CI run pending |

## Dependencies

- None on other plans. `plans/260703-2158-gh-206-risk-geo-hot-path-perf/` is
  merged (PR #209) and already reworked these scripts — this plan builds on the
  merged script shape (owner resolution + `fix_empty_contributors`).
- Related issues, explicitly **out of scope**: #201 (parse errors bypass the
  cache fallback via `?` — error-path semantics), #199 (closed by #209).

## Acceptance Criteria (from issue #198)

- [x] Empty contributors encodes as `[]`; new-actor-zero-deltas round-trips
      (done in PR #209; regression-guarded by existing conformance once CI runs it)
- [x] Decay contributor kind round-trips through serde (kind now encodes
      canonically as `"Decay"`; code review empirically showed the old
      `{"Decay":null}` form also parsed via serde_json's lenient unit-variant
      handling — the fix is canonicalization + new decay-path test coverage)
- [x] `is_new` true on first apply (parity with memory store; CI proof pending)
- [ ] Redis conformance tests run in CI (service container) — wired; awaiting
      PR CI run

## Open Questions

None — root causes are confirmed at exact lines; fixes are mechanical.

## Validation Log

### Session 1 — 2026-07-04
**Trigger:** Post-plan handoff — user selected `/ck:plan validate`.
**Questions asked:** 3

### Verification Results
- **Tier:** Standard (Fact Checker + Contract Verifier)
- **Claims checked:** 20
- **Verified:** 20 | **Failed:** 0 | **Unverified:** 0
- Key evidence: redis_lua.rs:120/:137/:261 confirmed via full file read;
  decay constants `MAX_DECAY=50`/`MIN_CLEAN_STREAK=10`/`DECAY_RATE=1` are
  `pub const` at decay.rs:12-18; memory `is_new` semantics memory.rs:139-164;
  `run_all` conformance.rs:17; `unique_prefix()` redis.rs:571; assertions
  conformance_redis.rs:72/77; ci.yml Test job `ubuntu-latest`, no services;
  coverage-check.sh:20 runs `cargo llvm-cov -p` without `--all-features`.
- Contract check `is_new`: all consumers (scorer.rs:265 → informational
  `ScorerResult.is_new`; assertions in store_trait.rs:190/225,
  redis_failover.rs:117, risk_key_collision_merge.rs:110/124/142,
  risk_scorer_decision_matrix.rs:137) assert correct semantics — none encode
  the bug; no enforcement path branches on the field.

#### Questions & Answers

1. **[Risk]** Phase 1 leaves already-corrupted Redis states (`{"Decay":null}`)
   to expire via TTL — no cleanup. Acceptable, or actively clean up?
   - Options: TTL self-heal (Recommended) | Lazy delete on parse fail | One-time SCAN cleanup
   - **Answer:** TTL self-heal
   - **Rationale:** No migration code; corrupted states are rare (decay needs
     10 clean requests first); error-path handling stays with #201.

2. **[Scope]** PR shape — phase 3 alone would turn CI red since gated tests
   currently fail against live Redis.
   - Options: Single PR (Recommended) | Two PRs, fixes first
   - **Answer:** Single PR
   - **Rationale:** The new CI job proves the fix in the same run; total diff
     is small (2 Lua lines + 1 test + yaml block).

3. **[Architecture]** `is_new` definition: Redis "state key absent" vs memory
   "owner not found" diverge in the expired-state-key edge.
   - Options: Accept + document (Recommended) | Match memory exactly
   - **Answer:** Match memory exactly
   - **Rationale:** Compute `is_new = (#candidates == 0)` at owner resolution
     (mint path). Exact cross-backend parity, including the transient edge
     where a converged owner's state key TTL-expired. User overrode the
     recommendation — parity wins over minimal diff.

#### Confirmed Decisions
- Bad-state remediation: TTL self-heal, no migration — #201 owns error path.
- Delivery: single PR containing all three phases.
- `is_new` semantics: owner-mint (`#candidates == 0`), not state existence.

#### Impact on Phases
- Phase 1: implementation step 1 rewritten (owner-mint `is_new`); success
  criterion added. Steps 2-4 unchanged.
- Phase 2: no change (test asserts observable behavior, backend-agnostic).
- Phase 3: no change.

### Whole-Plan Consistency Sweep
- Files reread: plan.md, phase-01-lua-script-fixes.md,
  phase-02-conformance-test-coverage.md, phase-03-ci-redis-service.md
- Decision deltas checked: 3
- Reconciled stale references: 2 (plan.md Overview bug-1 fix description;
  phase-01 step 1 + success criteria; GitHub issue comment corrected)
- Unresolved contradictions: 0
