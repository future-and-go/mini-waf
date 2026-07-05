---
title: "GH-195 risk enforcement: wire ScorerResult.action into inspect() decision"
description: "Consume ScorerResult.action (Block/Challenge) in WafEngine::inspect() so the FR-025 risk layer can actually enforce; wire the canary layer into the engine scorer"
status: completed
priority: P1
branch: "fix/gh-195-risk-action-enforcement"
tags: [security, risk, engine, bug]
blockedBy: []
blocks: []
created: "2026-07-04T16:49:55.653Z"
createdBy: "ck:plan"
source: skill
---

# GH-195 risk enforcement: wire ScorerResult.action into inspect() decision

## Overview

GitHub issue: https://github.com/future-and-go/mini-waf/issues/195 (P1, risk:security, CONFIRMED by multi-agent review 2026-07-03).

`WafEngine::inspect()` (`crates/waf-engine/src/engine.rs:681-686`) calls `self.scorer.score(...)` and keeps only `.score` via `map_or(0, |r| r.score)`. `ScorerResult.action` — computed by `threshold::decide` (threshold gate + pinned-actor override, `risk/scorer.rs:258-260`) and by the canary force-max path (`risk/scorer.rs:198-205`) — is discarded. Result: an actor at score 100 gets proxied with only an `X-WAF-Risk-Score: 100` header; the risk layer can never block or challenge.

All downstream plumbing already exists and is verified unused-but-ready:

- `Phase::RiskScore` (= 20) in `waf-common`.
- Mode registry maps `Phase::RiskScore → ("risk_assessment", Some("cumulative_risk"))` (`interop/checker_feature_map.rs:28`).
- Gateway renders `WafAction::Challenge` via FR-006 (`gateway/src/proxy_waf_response.rs:187-207`) and `WafAction::Block` via the block path.
- Community reporter already assigns confidence 0.65 to `Phase::RiskScore` events (`community/reporter.rs:92`).
- `send_audit_event` runs on every decision in the `inspect()` wrapper — risk blocks get audited for free.

What's genuinely missing: (a) the wrapper never maps the action into the returned `WafDecision`; (b) the engine's `Scorer` is built with `canary: None` and immediately `Arc`-wrapped (`engine.rs:253`), so the canary path is unreachable in production — but the issue's AC #2 requires a canary-driven 403.

## Ordering decision (issue AC #4)

The issue flagged "scoring runs before host-guard/whitelist/blacklist fast paths" — that was fixed by GH-206 Phase 3 (commit c37a8fe): scoring now runs after `inspect_pipeline()` and only when `FastPath::Miss`. The remaining deliberate placement decision, made here:

**Risk enforcement is an escalation-only gate at the wrapper.** It applies only when `fast_path == FastPath::Miss` **and** the pipeline decision's action is plain `WafAction::Allow`. It never overrides any decision carrying a detection — enforced blocks (SQLi, DDoS, rate limit, ...) *and* mode-downgraded LogOnly detections both keep their original decision (Validation Session 1: LogOnly'd detections are not escalated; the monitored feature's decision stays intact in the return value). A scorer `Allow` never downgrades anything. Fast-path exits (guard off, IP/URL allow/block lists) keep skipping scoring entirely per GH-206.

## Behavior gate

`RiskConfig::default()` has `enabled = false` → scorer returns score 0 / `Allow`. Production behavior is unchanged by this fix until operators wire a real config — that startup wiring is **#196** (separate issue, same root-cause family). Tests enable scoring per-test via `engine.replace_risk_config(...)` (existing pattern at `engine.rs:1225`).

## Intake

- Input type: change request (bug fix on accepted FR-025 behavior). Lane: **normal with stronger validation** (flags: existing behavior, client-visible contract — requests can now be 403'd/challenged when risk is enabled, weak proof — zero tests exercise enforcement).
- `scripts/bin/harness-cli` absent in working tree → story registration is a clean skip (GH-206 precedent); issue #195 is the tracked work item.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Engine enforcement wiring](./phase-01-engine-enforcement-wiring.md) | Completed |
| 2 | [Enforcement tests](./phase-02-enforcement-tests.md) | Completed |
| 3 | [Verification and docs](./phase-03-verification-and-docs.md) | Completed |

Phase 2 depends on Phase 1; Phase 3 runs last.

## Dependencies

- **#196** (risk admin API façade / startup config wiring): complementary, not blocking. This plan makes enforcement real once a config is loaded; #196 makes configs load in production. Neither blocks the other; both must land for end-to-end production enforcement.
- **Plan 260704-2309-gh-198-redis-riskstate-roundtrip** (branch `fix/gh-198-redis-riskstate-roundtrip`): touches `risk/store/redis*.rs` only — no file overlap with this plan (engine.rs, scorer.rs, canary.rs). No blocking relationship.
- **Plan 260703-2158-gh-206** (completed): this plan builds on its `FastPath` wrapper structure; no conflict.
- HTTP/3 listener (`gateway/src/http3.rs:304`) treats `Challenge` as pass-through — pre-existing gap for *all* challenge decisions (FR-006), not introduced here. Out of scope; noted for a follow-up issue.

## Validation Log

### Session 1 — 2026-07-05 (validate interview, 4 questions)

Verification pass (Standard tier): claims checked 14, Verified 14, Failed 0, Unverified 0. Key confirmations: `RequestCtx.tier_policy` is a pub `Arc<TierPolicy>` (types.rs:116) so the threshold-forcing test technique works; `Scorer::force_max` is pub (scorer.rs:348); disabled config early-returns Allow; `set_mode_registry` exists (engine.rs:555); `DdosCheck::ban_table()` accessor exists (checks/ddos/check.rs:76).

| # | Decision point | Answer | Effect |
|---|---------------|--------|--------|
| 1 | Escalation gate vs LogOnly'd detections | **Escalate plain Allow only** (rejects plan recommendation) | Gate condition is `matches!(decision.action, WafAction::Allow)`, not `is_enforcement_allowed()`. Monitored-feature detections keep their decision. |
| 2 | `ScorerReason` enum on `ScorerResult` | **No — single rule_name** (rejects plan recommendation) | All risk enforcement events log `rule_name = "cumulative_risk"`; no `ScorerResult` changes, no literal churn. Canary hits remain distinguishable only via the existing canary info log line. |
| 3 | Canary wiring scope | **Full FR-028 wiring** (expands scope) | Bind DDoS `DynamicBanTable` + config-driven `ban_ttl_secs` to the engine's `CanaryLayer`, not just paths. Consequence: post-canary requests block at the DDoS ban phase, so the pinned-actor test drives `force_max` directly. |
| 4 | Test shape | **Consolidate related cases** | ~4 testcontainers instead of 7 single-scenario tests. |

## Acceptance Criteria (from issue #195)

- [x] `inspect()` consumes `ScorerResult.action` and maps Block/Challenge into the pipeline decision (escalation-only, per ordering decision above) — `risk_threshold_matrix_enforced`.
- [x] Canary force-max produces an actual 403 in an integration test — `canary_hit_bans_and_pin_blocks` sub-case a (plus ban-table contract in sub-case b).
- [x] Pinned-actor override blocks in a test — `canary_hit_bans_and_pin_blocks` sub-case c.
- [x] Ordering placement decided deliberately and documented (done: escalation-only gate at wrapper, post-GH-206; `fast_path_exits_skip_risk_scoring` holds).

## Completion Log

- 2026-07-05: All phases done. waf-engine lib 1400 tests green (incl. 5 enforcement tests, verified under default and `--all-features`); fmt + clippy (`--all-targets --all-features -D warnings`) clean. Workspace `--no-fail-fast`: 3205 passed; all 315 failures are environmental testcontainer docker-socket `PermissionDenied` (local user not in docker group — CI runners cover these). Code review: ship-ready, no blocking findings (`plans/reports/code-reviewer-260705-0044-gh-195-risk-action-enforcement-report.md`). FR-025 story proof recorded here in lieu of `harness-cli` (absent in working tree, GH-206 precedent).
