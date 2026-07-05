---
phase: 2
title: "Enforcement tests"
status: completed
priority: P1
dependencies: [1]
---

# Phase 2: Enforcement tests

<!-- Updated: Validation Session 1 - consolidated to 4 tests; rule_name is always "cumulative_risk"; canary now IP-bans via DDoS table; pinned test drives force_max directly -->

## Overview

Prove enforcement end-to-end at the engine boundary: threshold block/challenge/disabled, canary 403 + IP ban, pinned-actor block, monitor-mode LogOnly, and no-override invariants. Covers issue ACs #2 and #3 plus the "weak proof" intake flag. Consolidated to ~4 testcontainer spin-ups (Validation S1).

## Requirements

- Functional: every scorer action variant observable through `engine.inspect()` return value.
- Non-functional: tests follow the existing inline-`#[cfg(test)]` pattern in `engine.rs` (PG testcontainer / `PG_TEST_URL`, `make_ctx`, `replace_risk_config`) — see `fast_path_exits_skip_risk_scoring` at `engine.rs:1204` as the template. Inline placement is required anyway: tests touch the private `scorer` field.

## Architecture

Score-forcing technique: `inspect()` calls `scorer.score(ctx, None, &[], None, now_ms)` with no deltas, so a clean request scores ~0. Rather than manufacturing L2 anomalies, drive `decide()` via `ctx.tier_policy.risk_thresholds` (swap in a custom `Arc<TierPolicy>`; `RequestCtx.tier_policy` is pub, types.rs:116):

- Block case: thresholds `{allow: 0, challenge: 0, block: 0}` → score 0 ≥ block → Block.
- Challenge case: `{allow: 0, challenge: 0, block: 101}` → score 0 in [allow, block) → Challenge.
- Allow case: defaults (`tier.rs:88`) with score 0 → Allow.

Canary and pinned cases don't need threshold games: the canary path force-maxes regardless; the pinned case drives `scorer.force_max` (pub, scorer.rs:348) directly — it must NOT reuse the canary-hit IP, because with the ban table wired (Phase 1) that IP gets blocked at the DDoS phase before scoring runs.

All risk enforcement events assert `rule_name == "cumulative_risk"` (single name, Validation S1).

## Related Code Files

- Modify: `crates/waf-engine/src/engine.rs` (inline `#[cfg(test)]` module — new tests alongside `fast_path_exits_skip_risk_scoring`).
- Modify (only if compile fallout from Phase 1): `crates/waf-engine/tests/risk_scorer_decision_matrix.rs`, `crates/waf-engine/tests/risk_scorer_extended.rs`.

## Implementation Steps

Four consolidated tests, one testcontainer each (Validation S1):

1. `risk_threshold_matrix_enforced` — one engine, three requests:
   a. block-at-0 thresholds → `WafAction::Block { status: 403, .. }`, `result.phase == Phase::RiskScore`, `rule_name == "cumulative_risk"`, `risk_score` attached (use distinct IPs per request to avoid state bleed);
   b. challenge-band thresholds → `WafAction::Challenge` with `Phase::RiskScore` result (gateway FR-006 rendering is existing covered behavior; the engine boundary is the contract here);
   c. swap in default (disabled) `RiskConfig` + block-at-0 thresholds → Allow (scorer short-circuits before `decide`).
2. `canary_hit_bans_and_pin_blocks` — canary config (`canary.enabled = true`, `paths = ["/admin-test"]`, explicit `ban_ttl_secs`) via `replace_risk_config`:
   a. request to `/admin-test` → Block 403, `Phase::RiskScore`, `rule_name == "cumulative_risk"`, score 100 (**issue AC #2**);
   b. follow-up request from the same IP to a normal path → blocked at the DDoS ban phase (result phase is the DDoS phase, not RiskScore) — asserts the FR-028 ban-table contract from Phase 1;
   c. from a **different** IP: call `scorer.force_max(ip, ttl_ms)` directly, then request a normal path with default thresholds → Block via pin override (`decide(_, _, true)`), `Phase::RiskScore` (**issue AC #3**).
3. `risk_block_respects_monitor_mode` — block-at-0 thresholds + mode registry putting `risk_assessment` in monitor (`set_mode_registry`, engine.rs:555) → decision carries Block intent downgraded to `mode: LogOnly`, `is_enforcement_allowed()` true (request proceeds, event logged).
4. `risk_never_overrides_pipeline_decisions` — block-at-0 thresholds, two requests:
   a. enforced case: SQLi payload (blacklist is a fast path; SQLi is not) → returned decision keeps the SQLi phase/rule, not `Phase::RiskScore`; `risk_score` still attached;
   b. LogOnly'd case: same SQLi payload with the SQLi feature in monitor mode → returned decision still carries the SQLi detection (mode LogOnly), NOT a risk escalation — asserts the plain-Allow-only gate (Validation S1 Q1).
5. Re-run `fast_path_exits_skip_risk_scoring` unmodified — fast-path invariant holds with enforcement wired.

## Success Criteria

- [x] All 4 new tests green under `cargo test -p waf-engine` (with Docker or `PG_TEST_URL`).
- [x] Issue AC #2 (canary → real 403) and AC #3 (pinned actor blocks) each map to a named assertion (test 2a / 2c).
- [x] LogOnly'd-detection non-escalation (Validation S1 Q1) covered by test 4b.
- [x] No existing test weakened or deleted.

## Risk Assessment

- **Cross-request state bleed**: consolidated tests share the risk store; use distinct client IPs per sub-case unless the test is deliberately exercising accumulated state (test 2 is).
- **Tier-policy mutability in `make_ctx`**: if `make_ctx` hardcodes tier policy, extend it with a thresholds override parameter locally in the test module — do not change production types.
- **DDoS-phase assertion (2b)**: exact phase/rule name for a dynamic ban block should be read from `checks/ddos/check.rs` at implementation time; assert on action Block + non-RiskScore phase if the ban surface is not a stable contract.
