# Red-Team Review: §3 WAF Decision Classes Plan

**Date:** 2026-05-29
**Plan:** `plans/260529-1536-s3-waf-decision-classes/`
**Reviewer:** Adversarial code-reviewer agent

## Summary

15 findings: 1 CRITICAL, 4 HIGH, 5 MEDIUM, 4 LOW. All addressed in plan files.

## Findings

### RT-01: Test struct-inits use 2-field WafDecision literal — HIGH
**Phase:** 3
**Issue:** 10 struct-init sites in test files (`proxy_waf_response_writer.rs` ×8, `types_decisions.rs` ×2) not listed in Phase 3 scope.
**Fix:** Added to Phase 3 Related Code Files + Step 11.

### RT-02: `const fn` over-removal from `allow()` — MEDIUM
**Phase:** 3
**Issue:** `allow()` can remain `const fn` — only uses literals and `None`.
**Fix:** Phase 3 note updated: only `block()` and new constructors lose `const`.

### RT-03: Phase 3→4 transition regression — CRITICAL
**Phase:** 3, 4
**Issue:** Between Phase 3 and 4, engine still produces `WafAction::LogOnly` with `mode: Enforce`. New `is_enforcement_allowed()` would return `false` → log_only traffic blocked.
**Fix:** `is_enforcement_allowed()` includes `WafAction::LogOnly` in match: `matches!(self.action, WafAction::Allow | WafAction::LogOnly) || self.mode == InteropMode::LogOnly`.

### RT-04: `risk_score` type mismatch — MEDIUM
**Phase:** 3
**Issue:** Plan used `u16`, `ScorerResult.score` is `u8` (range 0..=100).
**Fix:** Changed to `u8` throughout.

### RT-05: `risk_score` never wired from scorer — HIGH
**Phase:** 3, 5
**Issue:** No phase connects `ScorerResult.score` to `WafDecision.risk_score`. Field always 0.
**Fix:** Documented as deferred — scorer wiring belongs to §5 header injection plan.

### RT-06: `InteropMode` move not validated at workspace level — HIGH
**Phase:** 3
**Issue:** Phase 3 only ran `cargo test -p waf-common`. `waf-api` imports InteropMode from `waf-engine`.
**Fix:** Phase 3 validation changed to `cargo check --workspace`.

### RT-07: 2 additional log_only test assertions missed — LOW
**Phase:** 4
**Issue:** `engine_late_log_only_geo.rs` lines 108, 128 also assert `WafAction::LogOnly`.
**Fix:** Phase 4 Step 14 now explicitly lists both sites. Total: 6 assertions.

### RT-08: `RuleAction::Log` → `WafAction::LogOnly` conflates semantics — HIGH
**Phase:** 4
**Issue:** After deprecating `LogOnly`, rules with `RuleAction::Log` produce an action that gateway can't handle.
**Fix:** `RuleAction::Log` maps to `WafAction::Allow` — rule-author "log" intent = allow, log the match.

### RT-09: Body decision arms must return `Err` — MEDIUM
**Phase:** 6
**Issue:** New arms in `write_waf_body_decision` could return `Ok(())` instead of `Err`, bypassing security.
**Fix:** Phase 6 Step 3 now explicitly requires `Err` return.

### RT-10: Timeout/CircuitBreaker are dead code — MEDIUM
**Phase:** 2, 6
**Issue:** No code path produces these actions yet. Upstream wiring deferred.
**Fix:** Phase 7 compliance checklist annotated "type only, no producer yet."

### RT-11: Custom rules path bypasses `make_block_decision()` — MEDIUM
**Phase:** 4
**Issue:** Intentional but undocumented.
**Fix:** Documented in Phase 4 Step 9 with rationale.

### RT-12: `phase_display_covers_all_variants` test incomplete — LOW
**Phase:** 7
**Issue:** Pre-existing gap — missing phases 21-24.
**Fix:** Noted in Phase 7 as pre-existing.

### RT-13: `WafAction::LogOnly` serde removal path — LOW
**Phase:** 2
**Issue:** Stored events with `"log_only"` tag would break on variant removal.
**Fix:** Documented: keep deprecated variant until stored events age out.

### RT-14: `Redirect + LogOnly` behavior undocumented — MEDIUM
**Phase:** 3
**Issue:** Should redirect be skipped in log_only mode?
**Fix:** Yes — log_only means no enforcement. Documented.

### RT-15: `AuditEventType` lacks Timeout/CircuitBreaker variants — LOW
**Phase:** 2
**Issue:** Lossy mapping to `Block` for VictoriaLogs.
**Fix:** Acceptable — VictoriaLogs is secondary. JSONL uses `as_contract_str()` directly.

## Assessment: SHIP (after fixes applied)

All 15 findings addressed in plan files. RT-03 (CRITICAL) resolved with backward-compat match in `is_enforcement_allowed()`. Plan is viable for implementation.
