---
title: "GH-208 risk pipeline dead-code cleanup"
description: "Remove verified dead code (RiskKeyBuilder, unused Scorer ctors), unify force_max via reclamp(), and strip plan/phase/FR IDs from risk + ddos comments. Behavior-preserving."
status: pending
priority: P3
issue: https://github.com/future-and-go/mini-waf/issues/208
branch: "main-harness"
tags: [task, area:engine, cleanup, gh-208]
blockedBy: []
blocks: []
created: "2026-07-05T03:20:16.769Z"
createdBy: "ck:plan"
source: skill
---

# GH-208 risk pipeline dead-code cleanup

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/208 (P3 task, found by
multi-agent code review 2026-07-03). All claims re-verified on HEAD `9ee484b`
(2026-07-05) after merges #209/#210/#211. Behavior-preserving cleanup only —
delete, do not deprecate; no compatibility shims (YAGNI/KISS).

Four independent, verified cleanups plus one **dropped** claim:

1. **`RiskKeyBuilder` is dead** — `struct RiskKeyBuilder` + impls live at
   `crates/waf-engine/src/risk/store/store_trait.rs:76-116`. Only callers are its
   own two tests in the same file (`key_builder_with_each_axis` :195, and
   `key_builder_default_is_empty` :210). Production builds keys via
   `RiskKey::from_ip(...)` + direct field assignment (`scorer.rs:264-265`;
   `store_trait.rs:191` test also uses `from_ip`). Multi-axis `axis_count()`
   coverage is independently held by `key.rs:161-172` (`axis_count_combinations`
   asserts 0/1/2/3), so removing the builder tests loses no coverage. **CONFIRMED.**
2. **`Scorer::with_seed` / `with_velocity_threshold` are dead in production** —
   `scorer.rs:77` and `scorer.rs:91`. Only callers are constructor-exercising
   tests: `with_seed` at `tests/risk_scorer_extended.rs:156`, `with_velocity_threshold`
   at `tests/risk_scorer_extended.rs:172`. Production always uses `new()`
   (`scorer.rs:63`). `set_seed(&mut self)` already exists (`scorer.rs:104`), so the
   seed test migrates to `new()` + `set_seed()`. No `set_velocity_threshold` setter
   exists; velocity-breach behavior is covered by the real pipeline test
   `tx_velocity_integration.rs:242`, so the dedicated ctor test is removed outright
   (no setter added — YAGNI). **CONFIRMED.**
3. **`force_max` bypasses `reclamp()`** — `store/memory.rs:183-184` manually sets
   `raw_score = 100; clamped_score = 100;` instead of setting `raw_score = 100` then
   calling `RiskState::reclamp()` (`state.rs:128-133`), the canonical derivation used
   by `fold` (`score.rs:28`) and `apply_decay` (`decay.rs:46`). Equivalent today;
   drifts if clamp rules change. Redis `FORCE_MAX_SCRIPT` (`redis.rs:81,115`) parity
   duplication is intentional and untouched. **CONFIRMED.**
4. **Plan/phase/FR IDs in comments** — 87 hits of `Phase |phase-|FR-0|§.*plan` across
   `crates/waf-engine/src/risk/**` and `crates/waf-engine/src/checks/ddos/**` (e.g.
   `scorer.rs:6`, `config.rs:61`, `seed/mod.rs:1`, `checks/ddos/action/risk.rs:1`,
   `aggregator_impl.rs:27`). Violates `.claude/rules/review-audit-self-decision.md:32-34`
   (explain invariants directly). **CONFIRMED.**

### Dropped claim (no longer holds on HEAD)

- **`UpdateResult.ipv4_updated` / `ipv6_updated` are NOT dead.** The issue called them
  "never read", but on HEAD they are read at **7 sites**: `prx-waf/src/main.rs:414,417,
  437,439,442` (CLI `geoip download`/`update` output) and `geoip_updater.rs:156,242`
  (update-applied guard + auto-updater log), plus asserts in
  `tests/geoip_updater_schedule.rs:338-339`. They carry real signal: `update()` returns
  `UpdateResult::default()` (bools `false`) when files are fresh/skipped
  (`geoip_updater.rs:151`), so the bool distinguishes "skipped" from "downloaded".
  Removing them is a behavioral refactor (rewrite 7 callers + reshape a `pub`
  re-exported struct at `lib.rs:32` + change CLI output), not dead-code removal —
  **out of scope** for this behavior-preserving cleanup. `geoip_updater.rs` is owned by
  the **GH-205** plan, which already schedules a `download()` reshape and explicitly
  coordinates on this struct. Defer any `UpdateResult` change to GH-205.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Remove dead RiskKeyBuilder + its tests](./phase-01-remove-dead-code-riskkeybuilder.md) | Pending |
| 2 | [Remove unused Scorer ctors + migrate tests](./phase-02-unused-scorer-ctors.md) | Pending |
| 3 | [force_max via reclamp() unification](./phase-03-force-max-via-reclamp-unification.md) | Pending |
| 4 | [Comment + test-name sweep (strip plan/phase/FR IDs)](./phase-04-comment-and-test-name-sweep-strip-plan-phase-fr-ids.md) | Pending |

Phases are **sequential** (P3 cleanup, no parallelism). Intra-plan file overlap
(scorer.rs appears in Phase 2 code + Phase 4 comments) is fine because phases run
one at a time; do Phase 4's comment sweep last so it covers lines the earlier
phases leave behind.

## Key Decisions

- **`with_velocity_threshold` removed without a setter.** The issue floated adding a
  `set_velocity_threshold` setter or `new()` param to keep the test working. Rejected:
  the only consumer is a dead-ctor test, and velocity-breach behavior is already covered
  end-to-end by `tx_velocity_integration.rs:242`. Adding an API to satisfy a test we are
  deleting violates YAGNI. Delete ctor + delete its dedicated test.
- **`with_seed` test migrated, not deleted.** `with_seed_constructor_and_set_seed`
  (`risk_scorer_extended.rs:148`) also exercises `set_seed` + a live `score()` call, so it
  has value beyond the ctor. Swap `Scorer::with_seed(store, swap, seed)` → `Scorer::new(store,
  swap)` and rename the test to describe behavior (drop "constructor" from the name so it
  does not re-embed a removed API).
- **`force_max` touches memory backend only.** Redis `FORCE_MAX_SCRIPT` parity is
  intentional per the issue; leave the Lua path alone. Equivalence is already asserted by
  cross-backend conformance (`store/conformance.rs:65` clamped==100; redis
  `conformance_redis.rs:179`), so no new test is required — the existing gate proves it.
- **Comment sweep strips requirement IDs too.** `FR-0xx` are "finding codes" under the
  repo rule, not just plan/phase numbers. Rewrite `//! FR-025 risk scoring configuration.`
  → `//! Risk scoring configuration.` etc. — describe behavior, drop the label. Scope is
  strictly `risk/**` + `checks/ddos/**` (the two dirs named in the AC grep). Do not touch
  comments elsewhere.
- **No `list_risk_actors`/API changes here.** Pure cleanup; no public contract moves.

## Cross-Plan Dependencies (soft ordering — no hard blockedBy)

All overlaps are trivially rebaseable (disjoint code regions or comment-only edits), so
none block. Land GH-208 **after** the higher-priority behavioral plans below, or rebase
whichever lands second.

- **GH-196** (`260705-0953-gh-196-risk-admin-api-engine-wiring`): Phase 1 relaxes the
  `Scorer` bound to `S: RiskStore + ?Sized` on the same `impl` block that holds the ctors
  removed in Phase 2 (`scorer.rs`), and adds `RiskStore::clear` to `store_trait.rs` (Phase 2
  here removes `RiskKeyBuilder` from the same file); Phase 4 wires the purge loop in
  `memory.rs` (Phase 3 here edits `force_max` in the same file). **Verified GH-196 does NOT
  repurpose `with_seed`/`with_velocity_threshold`/`RiskKeyBuilder`** (phase-01 mentions none),
  so no defer is needed — but land GH-196 first and rebase these deletions to avoid churn.
- **GH-204** (`260705-0958-gh-204-risk-delta-cap-decay-config`): edits decay consts +
  scorer wiring (`scorer.rs`, `decay.rs`, `config.rs`). Overlaps Phase 4 comments only.
- **GH-205** (`260705-0958-gh-205-geoip-updater-hardened-fetch`): owns `geoip_updater.rs`
  and already plans a `download()` reshape. Its plan assumes GH-208 removes the
  `UpdateResult` bools — that assumption is **stale** (bools are live on HEAD, see Dropped
  claim). GH-208 leaves `geoip_updater.rs` untouched; GH-205 owns any `UpdateResult` change.
- **GH-202** (`260705-0739-gh-202-riskbump-actor-keyed-submit`): rewrites
  `checks/ddos/action/risk.rs` + `aggregator_impl.rs` — the exact files whose header
  comments Phase 4 rewrites (`risk.rs:1` "FR-005 phase-05", `aggregator_impl.rs:27` "§3.3 of
  the plan"). Land Phase 4's ddos sweep after GH-202, or let GH-202 fold those comment fixes
  in.

## Acceptance Criteria (from issue)

- [ ] Dead items removed with their dedicated tests: `RiskKeyBuilder` (P1), `Scorer::with_seed`
      + `with_velocity_threshold` (P2). `UpdateResult` bools deliberately **not** removed —
      claim no longer holds; deferred to GH-205 (documented above).
- [ ] `force_max` derives `clamped_score` via `reclamp()` (P3); cross-backend conformance green.
- [ ] `grep -rn "Phase |phase-|FR-0|§.*plan" crates/waf-engine/src/risk crates/waf-engine/src/checks/ddos`
      returns no comment/test-name hits (P4).
- [ ] Full workspace `cargo test` + `clippy --all-targets` + `fmt --check` green; no behavior change.

## Validation

- `cargo test -p waf-engine` (unit + integration) green, incl. `store::conformance` and
  redis-gated `conformance_redis` (`REDIS_TEST_URL`) for `force_max` parity.
- `cargo clippy --workspace --all-targets -- -D warnings` clean (dead-code removal must not
  leave unused imports/`SeedLayer` refs in the test file).
- `cargo fmt --all --check` clean.
- Post-sweep grep assertion (AC above) returns zero hits.
