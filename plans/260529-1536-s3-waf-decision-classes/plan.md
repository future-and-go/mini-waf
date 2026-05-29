---
title: "§3 WAF Decision Classes — Interop Contract v2.3 Compliance"
description: "Extend WafAction with 3 missing decision classes, enrich WafDecision with contract metadata, fix log_only semantics, update gateway response handler — all via TDD"
status: pending
priority: P1
branch: "main"
tags: [interop, contract, benchmark, s3-decision-classes, tdd]
blockedBy: []
blocks: [260527-1157-waf-interop-v23-critical-compliance]
created: "2026-05-29T08:39:44.060Z"
createdBy: "ck:plan"
source: skill
---

# §3 WAF Decision Classes — Interop Contract v2.3 Compliance

## Overview

Contract v2.3 §3 requires 6 decision classes: `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`. Current `WafAction` has only 3 of these (`Allow`, `Block`, `Challenge`). Rate-limit detections map to `Block { status: 403 }`, timeout/circuit-breaker scenarios produce generic 502/503 errors outside the WAF decision taxonomy.

Additionally, `WafDecision` lacks contract-required metadata fields (`risk_score`, `mode`, `rule_id`), and log_only mode replaces the intended action with `WafAction::LogOnly` instead of preserving it.

**Design pattern: Additive enum extension + builder enrichment.** No existing variants removed. New fields use defaults so existing struct-init patterns compile unchanged. The `Check` trait stays untouched — action mapping happens in the engine's decision-assembly layer.

**Source:** `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` §3, §5.2/§6
**Contract:** `analysis/docs/EN_waf_interop_contract_v2.3.md` §3 (lines 285–313)
**Related plan:** `plans/260527-1157-waf-interop-v23-critical-compliance/` (Phase 1 overlap — this plan supersedes its §3 scope)

## Design Principles

1. **Additive-only enum changes** — `RateLimit`, `Timeout`, `CircuitBreaker` added; `LogOnly` deprecated; `Redirect` kept (internal use)
2. **Phase-aware action mapping** — Engine inspects `DetectionResult.phase` to select the correct `WafAction` variant instead of hardcoding `Block { status: 403 }`
3. **Builder pattern for WafDecision** — `with_risk_score()`, `with_mode()` chainable methods; existing constructors gain default metadata values
4. **Mode separation** — log_only is a mode on `WafDecision`, not an action. `InteropMode` (already exists in `waf_engine::interop`) reused
5. **Zero-breakage** — All existing tests must pass unchanged before any new test is added. `#[deprecated]` annotations guide migration.

## Architecture Impact

```
waf-common/src/types.rs
  WafAction  ← add RateLimit{status,body}, Timeout{status}, CircuitBreaker{status,body}
  WafAction  ← deprecate LogOnly, add as_contract_str()
  WafDecision ← add risk_score:u8, mode:InteropMode, rule_id:Option<String>
  WafDecision ← add with_risk_score(), with_mode(), is_enforcement_allowed()
  WafDecision ← deprecate is_allowed(), keep as wrapper

waf-engine/src/engine.rs
  inspect()  ← 11 log_only_mode branches: preserve intended action, set mode=LogOnly
  inspect()  ← Phase::RateLimit results → WafAction::RateLimit{429}

gateway/src/proxy_waf_response.rs
  write_waf_decision()  ← add match arms for RateLimit, Timeout, CircuitBreaker
  write_waf_decision()  ← mode-aware: LogOnly skips enforcement

gateway/src/proxy.rs
  fail_to_proxy()  ← transport timeout → WafAction::Timeout{504}
                   ← transport unresponsive → WafAction::CircuitBreaker{503}

engine logging helpers (3 match blocks)
  log_attack(), log_security_event(), send_audit_event()
  ← add arms for RateLimit, Timeout, CircuitBreaker
```

## Phases

| Phase | Name | Status | Priority | Effort | Dependencies |
|-------|------|--------|----------|--------|--------------|
| 1 | [TDD Test Scaffold](./phase-01-tdd-test-scaffold.md) | Pending | P1 | 2h | None |
| 2 | [WafAction Enum Extension](./phase-02-wafaction-enum-extension.md) | Pending | P1 | 2h | Phase 1 |
| 3 | [WafDecision Enrichment](./phase-03-wafdecision-enrichment.md) | Completed | P1 | 2h | Phase 2 |
| 4 | [Engine log_only Semantic Fix](./phase-04-engine-log-only-semantic-fix.md) | Done | P1 | 3h | Phase 3 |
| 5 | [Rate-Limit Action Mapping](./phase-05-rate-limit-action-mapping.md) | Done | P1 | 1h | Phase 3 |
| 6 | [Gateway Response Handler Update](./phase-06-gateway-response-handler-update.md) | Done | P1 | 2h | Phases 2,3 |
| 7 | [Validation and Regression](./phase-07-validation-and-regression.md) | Pending | P1 | 1h | Phases 1-6 |

**Total estimated effort:** ~13h (1.5-2 days)

## Dependencies

- Phases 4 and 5 can run in **parallel** after Phase 3 (independent: engine semantics vs action mapping)
- Phase 6 depends on Phases 2+3 (needs new variants + enriched struct)
- Phase 7 is the integration gate

## PR Strategy (Validation Interview)

**One PR per phase.** Each phase is independently deployable because:
- RT-03 fix ensures `is_enforcement_allowed()` handles `WafAction::LogOnly` backward-compat
- Each phase runs `cargo check --workspace` before merge
- Phase 7 PR is the final validation gate

## Relationship to Parent Plan

This plan **supersedes** Phase 1 of `plans/260527-1157-waf-interop-v23-critical-compliance/`. That plan's Phase 1 ("Core Type System Refactor §3 + log_only") covers the same scope but this plan provides deeper TDD structure and phase-aware action mapping detail. Once this plan completes, mark Phase 1 of the parent plan as completed.

## Red-Team Findings Applied

15 findings from adversarial review. Key fixes incorporated:

| ID | Severity | Fix Applied |
|----|----------|-------------|
| RT-01 | HIGH | Phase 3 scope expanded: add all struct-init sites in test files (proxy_waf_response_writer.rs, types_decisions.rs) |
| RT-02 | MEDIUM | Keep `allow()` as `const fn`; only remove `const` from `block()` and new constructors |
| RT-03 | CRITICAL | `is_enforcement_allowed()` also matches `WafAction::LogOnly` for backward compat during transition |
| RT-04 | MEDIUM | `risk_score` changed from `u16` to `u8` to match `ScorerResult.score` |
| RT-05 | HIGH | Acknowledged as deferred — `risk_score` defaults to 0; scorer wiring is out of scope (separate §5 plan) |
| RT-06 | HIGH | Phase 3 validation changed to `cargo check --workspace` (not just `-p waf-common`) |
| RT-07 | LOW | Phase 4 explicitly lists 6 test assertions to update (4 in log_only + 2 in late_log_only_geo) |
| RT-08 | HIGH | `RuleAction::Log` maps to `WafAction::Allow` (not LogOnly); rule-author "log" intent → Allow + mode decision |
| RT-09 | MEDIUM | Phase 6 Step 3 explicitly requires `Err` return from body decision arms |
| RT-10 | MEDIUM | Phase 7 compliance checklist notes timeout/circuit_breaker as "type-only, no producer yet" |
| RT-11 | MEDIUM | Custom rules path bypass of `make_block_decision()` documented |
| RT-12 | LOW | Noted as pre-existing test gap in Phase 7 |
| RT-13 | LOW | `WafAction::LogOnly` must remain until stored events age out; documented |
| RT-14 | MEDIUM | `Redirect + LogOnly` skips redirect — documented as correct (log-only means no enforcement) |
| RT-15 | LOW | `AuditEventType` already has `RateLimit`; map Timeout/CB to `Block` (lossy, acceptable for VictoriaLogs) |

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| New `WafAction` variants break exhaustive matches | Compile error (safe) | `cargo check --workspace` catches all; add arms before adding variants |
| `is_allowed()` deprecation breaks callers | 10+ call sites | Keep as wrapper calling `is_enforcement_allowed()`; deprecation warning guides migration |
| log_only refactor misses a branch | Engine behavior change | grep-verified 11 branches; test each detection phase explicitly |
| Serde backward compat for stored events | Medium | New tags additive; `LogOnly` kept deprecated until stored events age out |
| `WafDecision` field additions break struct-init | Compile error | Update all struct-init sites (engine, checker, gateway tests, waf-common tests) |
| Phase 3→4 transition regression (RT-03) | log_only traffic blocked | `is_enforcement_allowed()` includes `WafAction::LogOnly` in match |
| `risk_score` always 0 (RT-05) | Contract §5 partial compliance | Documented as deferred; scorer wiring belongs to §5 header injection plan |
| Timeout/CircuitBreaker no producer (RT-10) | Dead code temporarily | Types ready; upstream wiring deferred to §8 binary contract |

## Unresolved Questions

1. **RuleAction::Log post-deprecation**: Currently maps to `WafAction::Allow` (RT-08 fix). If rule authors expect "log but still block" semantics, this needs revisiting. Current interpretation: "log" intent = allow request, log the match.
2. **risk_score wiring**: Scorer output not connected to WafDecision in this plan. Separate work needed for §5 compliance (X-WAF-Risk-Score header).
3. **Timeout/CircuitBreaker producers**: Need upstream health-check wiring in §8 binary contract plan to produce these actions.
