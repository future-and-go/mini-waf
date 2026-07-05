# GH-195 Risk Action Enforcement: 3-Phase Plan + Validation Complete

**Date:** 2026-07-05 00:04 +07:00
**Severity:** High
**Component:** waf-engine (risk scorer, canary layer, decision wrapper)
**Status:** Plan validated; ready for Phase 1 implementation

## What Happened

Created a 3-phase plan for GitHub issue #195 (P1, security): the risk layer computes Block/Challenge decisions via `ScorerResult.action` but `WafEngine::inspect()` discards them (`map_or(0, |r| r.score)` keeps only the score). Consequence: the FR-025 risk enforcement feature is wired but unreachable in production. Secondary discovery: the engine builds `Scorer` with `canary: None` then immediately Arc-wraps it, making the FR-028 canary force-max path unreachable. Generated the plan via `/ck:plan --github`; posted plan comment to issue #195. Conducted validation interview (4 questions); verified 14 plan claims against source (0 failed). Interview reversed two design recommendations and expanded the canary scope: escalation gate narrowed to plain-Allow-only (LogOnly'd detections stay untouched), dropped a proposed `ScorerReason` enum (all risk events use single `rule_name = "cumulative_risk"`), and wired full FR-028 canary (DDoS ban table + config-driven TTL, not just paths). Consolidated test shape (7 → 4 testcontainers). Posted corrective comment to issue #195 capturing decisions.

Plan structure: Phase 1 (engine wiring), Phase 2 (enforcement tests), Phase 3 (verification and docs). Phase 2 depends on Phase 1; Phase 3 runs last.

## The Brutal Truth

This planning session was clean. Grep verification succeeded (14 claims checked, 0 failed). The validation interview landed decisive choices that deviate from the recommended design but make engineering sense — escalate-only gate (plain Allow) is simpler than monitoring-aware escalation, single rule name avoids churn in `ScorerResult`, and full canary wiring (with DDoS ban table + config TTL) is the feature-complete version, not the minimal one. The test consolidation (7 → 4) trades scenario granularity for clarity.

The one friction point: couldn't apply the `ready to review` label to #195 because the GitHub token is read-only on the repo. The decision comment went into the issue anyway, so the artifact is complete; the label is cosmetic.

## Technical Details

**The bugs:**
- `inspect()` line 685 (engine.rs): `map_or(0, |r| r.score)` reads the score but discards `ScorerResult.action` (Block/Challenge/Allow).
- Canary construction (line 253, engine.rs): `Scorer::new()` called with `canary: None` *before* the layer exists; then `Arc::new(scorer)` wraps it immutably. `Scorer::set_canary` is defined (scorer.rs:109) but unreachable after Arc-wrap.

**Verification successes:** Ordering placement already fixed by GH-206 Phase 3 (commit c37a8fe) — scoring runs after `inspect_pipeline()` on `FastPath::Miss` only, not before. `Phase::RiskScore` and mode registry entry exist and are wired (interop/checker_feature_map.rs:28). Gateway renders Block/Challenge. Community reporter already assigns confidence 0.65 to RiskScore events. `RequestCtx.tier_policy` is public Arc (types.rs:116) for test forcing. `DdosCheck::ban_table()` accessor exists (checks/ddos/check.rs:76). `CanaryLayer::with_ban_table` constructor exists (canary.rs:60).

**Scope fold to consider:** Issue #195 AC #4 is already met by GH-206 (scoring placement is post-pipeline, not pre); this plan defines the deliberate placement as "escalation-only gate at wrapper, applies only when pipeline action is plain Allow."

## What We Tried

**Decision point Q1: Escalation gate behavior vs LogOnly'd detections**
- Recommended: `is_enforcement_allowed()` check (monitoring-aware escalation).
- User chose: plain `matches!(decision.action, WafAction::Allow)` (escalate Allow only; detections downgraded to LogOnly keep their decision).
- Rationale: simpler; monitored features shield their actors from risk escalation (accepted trade-off, called out in risk docs).

**Decision point Q2: `ScorerReason` enum on `ScorerResult`**
- Recommended: add enum to distinguish canary hits from threshold hits in decision output.
- User chose: no enum; all risk events log `rule_name = "cumulative_risk"` (single static name; canary hits remain distinguishable only via existing canary log line).
- Rationale: avoids churn in `ScorerResult` type; reduces `Phase 1` code.

**Decision point Q3: Canary wiring scope**
- Recommended: wire paths only (minimal scope).
- User chose: full FR-028 wiring (DDoS ban table + config-driven `ban_ttl_secs`).
- Rationale: feature-complete; ban table reuse means post-canary requests block at the DDoS phase, which is the intended behavior. Test consequence: pinned-actor test now drives `force_max` on a separate IP (pinned actor itself will be in the ban table after first canary hit).

**Decision point Q4: Test shape**
- Consolidate 7 single-scenario tests into ~4 testcontainer groups (related cases per container).

## Root Cause Analysis

**Why enforcement was unreachable:**
- `inspect()` was written to extract `.score` only, leaving the decision field unused. No explicit rejection of enforcement; just incomplete integration.
- Scorer was constructed with `canary: None` (the layer didn't exist yet in the constructor call graph) and immediately Arc-wrapped, preventing `set_canary` from being called later. This was an ordering bug in `WafEngine::new`, not a design flaw.

**Why this wasn't caught earlier:**
- No integration tests exercise `inspect()` with `ScorerResult.action != Allow` (weak proof on the feature).
- The FR-028 canary layer was built on the assumption that it would be installed post-construction; the Arc-wrap assumption broke that contract silently.

## Lessons Learned

1. **Validation interviews should force explicit choice between alternatives.** The three reversed/expanded decisions are all sound; the recommended versions would have worked but cost code or completeness. Framing as trade-offs (simpler code vs feature-complete) drives better choices.

2. **Completeness matters when features are interdependent.** Full canary wiring (DDoS table + config TTL) is better than paths-only because the ban-table block is the natural enforcement point; partial wiring would leave the feature fragmented.

3. **LogOnly'd detections as a shield is an accepted trade-off, not a bug.** Operators who leave features in monitor mode with risk enforcement active will see risk escalation suppressed for those requests. Document this clearly so it's not surprising.

4. **Claim verification at plan time catches constructor bugs.** Checking `Arc::new(scorer)` line 253 and `set_canary` definition location (unreachable after Arc-wrap) surfaced the ordering issue that would otherwise have required runtime testing to find.

## Next Steps

- [x] Plan generated via `/ck:plan --github` (complete).
- [x] 14 claims verified against source (complete, 0 failed).
- [x] Validation interview (4 decisions captured; complete).
- [x] Corrective comment posted to issue #195 (complete; cannot apply label due to token perms).
- [ ] Phase 1 implementation: add `risk_canary` field, construct with DDoS ban table, install on scorer pre-Arc-wrap, wire decisions in `inspect()`, extend canary TTL reload.
- [ ] Phase 2: 4 testcontainers covering Allow-to-Block, Allow-to-Challenge, pinned-actor force-max on separate IP, monitor-mode LogOnly downgrade.
- [ ] Phase 3: rollout docs (enable risk scoring via #196 first, then enable enforcement thresholds via config).
- [ ] Note for next session: GitHub token is read-only; `ready to review` label cannot be applied via bot.

---

**Status:** DONE
**Summary:** 3-phase plan created and validated; 14 claims verified, 0 failed. Validation interview reversed two design choices (escalation gate, enum scope) and expanded canary wiring to full FR-028. Ready to implement Phase 1.
**Concerns/Blockers:** None blocking. Label automation unavailable (read-only token).
