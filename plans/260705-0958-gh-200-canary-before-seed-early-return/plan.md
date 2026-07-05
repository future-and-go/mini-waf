---
title: "GH-200 risk: run canary check before seed-layer early return"
description: "Fix the seed-Score early return in the scorer that skips the canary honeypot check for Tor/datacenter IPs — restore the documented whitelist → canary → other-layers ordering"
status: completed
priority: P2
issue: https://github.com/future-and-go/mini-waf/issues/200
branch: "main-harness"
tags: [bug, area:engine, risk, security, gh-200]
blockedBy: []
blocks: []
created: "2026-07-05T03:00:30.698Z"
createdBy: "ck:plan"
source: skill
effort: 1h
---

# GH-200 risk: run canary check before seed-layer early return

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/200 (bug, CONFIRMED by
multi-agent code review 2026-07-03; all claims re-verified on HEAD `9ee484b`,
2026-07-05 after #209/#210/#211 shifted line numbers).

`Scorer::score` evaluates the L0 seed layer first, and the `SeedVerdict::Score`
arm returns early:

- `crates/waf-engine/src/risk/scorer.rs:168-175` — on `SeedVerdict::Score { delta, kind }`,
  the arm builds a seed contributor and `return self.score_with_l2(...).await`.
- The FR-028 canary block lives *after* that early return at
  `crates/waf-engine/src/risk/scorer.rs:180-206` (`canary.check_and_ban` →
  `force_max` → `Block { 403, "canary_honeypot" }`).
- Result: any IP the seed layer scores — Tor exits (`SeedKind::TorExit`, delta 30),
  datacenter/bad ASNs (`SeedKind::DatacenterASN`/`BadASN`) — never reaches the
  canary block. `check_and_ban` never runs, so no `force_max`, no
  `DynamicBanTable` insert (`crates/waf-engine/src/risk/canary.rs:99-121`), no 403.
  The scanner accrues a small seed delta and keeps probing the honeypot path.

The comment at `scorer.rs:180-181` states canary runs "AFTER whitelist, BEFORE
other layers" — the seed early-return silently contradicts it. This is a
control-flow ordering bug, not a logic bug in either layer.

**Documented ordering to restore:** whitelist (short-circuit Allow) → canary
(force_max + Block) → seed-Score contributor + L2 layers. Whitelist must still
win over canary (a whitelisted IP hitting a canary path is Allowed — already
covered by `whitelist_bypasses_canary`, `risk/tests/canary.rs:269-322`).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Reorder canary check before seed-Score early return](./phase-01-reorder-canary-check-before-seed-score-early-return.md) | Completed |
| 2 | [Acceptance test + quality gates](./phase-02-acceptance-test-quality-gates.md) | Completed |

## Key Decisions

- **Evaluate the seed verdict once, then branch.** Restructure `score()` so
  `seed.evaluate(ctx.client_ip)` is called into a local `SeedVerdict`; the
  `Whitelisted` arm returns Allow immediately (short-circuit preserved), then the
  canary block runs unconditionally, then the `Score` arm feeds its contributor
  into `score_with_l2`. This keeps a single seed lookup and makes the ordering
  match the comment. Rationale: KISS — reordering, not new abstractions; avoids
  duplicating the canary block into both the `Score` and `None` paths (DRY).
- **Whitelist keeps priority over canary.** The `Whitelisted` early return stays
  *before* the canary block, so `whitelist_bypasses_canary` remains green
  unchanged. Only the `Score` path moves relative to canary.
- **No signature/API change.** `score`, `score_with_l2`, `check_and_ban`,
  `force_max` are untouched. Pure intra-function control-flow edit in `score()`.
- **Update the stale ordering comment** in the same edit so the code and its
  documented invariant agree (comment states the invariant, no plan/FR codes per
  repo rule).

## Cross-Plan Dependencies

- **GH-204 (delta cap wiring)** also edits `scorer.rs` around the delta-assembly
  path. No hard block — this plan touches `score()` control flow (seed/canary
  ordering); GH-204 touches delta clamping inside `score_with_l2`. Implementation
  ordering note only: whichever lands first, the other rebases the small textual
  overlap in `scorer.rs`. Land this first if possible — it is smaller and its
  test locks the ordering invariant GH-204 must not re-break.
- **GH-196 (scorer over `dyn RiskStore`)** changes the `Scorer<S>` bound and
  engine wiring, not `score()` internals. No overlap with this fix.

## Acceptance Criteria (from issue)

- [x] Canary check evaluated before (or independently of) the seed early-return. → Phase 1
- [x] Test: a seed-classified IP (Tor exit) hitting a canary path gets `force_max`
      + `DynamicBanTable` entry + `Block`. → Phase 2

## Validation

- `cargo test -p waf-engine risk` green (new + existing canary/seed tests).
- New test asserts: `WafAction::Block`, `score == 100`, `ban_table.contains(ip, now_ms)`,
  and a pinned store state (`force_max` applied) for a Tor-exit IP on a canary path.
- `whitelist_bypasses_canary` and `canary_path_triggers_block_and_score_100`
  still pass (ordering invariant intact both directions).
- `cargo clippy -p waf-engine --all-targets` clean.
