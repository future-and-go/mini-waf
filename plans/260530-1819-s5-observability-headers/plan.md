---
title: "§5 Mandatory Observability Headers — Interop Contract v2.3 Compliance"
description: "Inject all 6 X-WAF-* response headers on EVERY HTTP response egress path (11 paths) via a single DRY injector + ctx snapshot, ordered after FR-035 and outside the cache-capture set, wired through TDD"
status: pending
priority: P1
branch: "main"
tags: [interop, contract, benchmark, s5-observability-headers, tdd]
blockedBy: []
blocks: [260527-1157-waf-interop-v23-critical-compliance]
created: "2026-05-30T18:19:00.000Z"
createdBy: "ck:plan"
source: skill
redTeam: "plans/reports/from-red-team-to-planner-s5-observability-headers-260530-1819-report.md"
---

# §5 Mandatory Observability Headers — Interop Contract v2.3 Compliance

## Overview

Contract v2.3 §5 mandates 6 observability headers on **every** HTTP response. None are
emitted today (gap report §5). The §3 work (completed) built the data-source *fields*
(`WafAction::as_contract_str()`, `InteropMode::as_contract_str()`, `WafDecision.{risk_score,mode,rule_id}`,
`RequestCtx.req_id`, `dominant_contributor()`). This plan plumbs those values into **all 11
response egress paths**.

> ⚠️ **`risk_score` is hardcoded `0`** today; `engine.inspect()` (engine.rs:538) does NOT
> invoke the `Scorer`. **Decision (validate): wire the `Scorer` into decision assembly in this
> plan (Phase 3)** so `X-WAF-Risk-Score` and `X-WAF-Rule-Id` (`dominant_contributor`) are real,
> not `0`/`none`. This is firm scope (RiskStore/config/RiskKey threading), not deferred.

| Header | Value source | Format |
|---|---|---|
| `X-WAF-Request-Id` | `RequestCtx.req_id` (UUID v4) | UUID string |
| `X-WAF-Risk-Score` | `WafDecision.risk_score` (clamp 0–100) | integer `0`–`100` |
| `X-WAF-Action` | `WafAction::as_contract_str()` | `allow`/`block`/`challenge`/`rate_limit`/`timeout`/`circuit_breaker` |
| `X-WAF-Rule-Id` | `WafDecision.rule_id` / `dominant_contributor()`; `none` fallback | `[A-Za-z0-9-]+` or `none` |
| `X-WAF-Cache` | new `CacheStatus` enum | `HIT`/`MISS`/`BYPASS` |
| `X-WAF-Mode` | `InteropMode::as_contract_str()` | `enforce`/`log_only` |

## Egress Path Inventory (the contract surface)

ALL of these must emit the 6 headers. Original plan covered ~5; red-team found the rest.

| # | Egress path | Code location | Pre/post `inspect()` | Phase |
|---|---|---|---|---|
| 1 | Header-inspect block/rate_limit/timeout/circuit_breaker | `write_waf_decision` (proxy_waf_response.rs:30) | post | 4 |
| 2 | Header-inspect redirect (302) | `write_waf_decision` Redirect arm | post | 4 |
| 3 | Challenge page served | `handle_challenge` (proxy_waf_response.rs:109) | post | 4 |
| 4 | **Body-inspect block/rate_limit/timeout/redirect** | `write_waf_body_decision` (proxy_waf_response.rs:204) | post | 4 |
| 5 | **Access-gate block (pre-WAF 403)** | `request_filter` access-gate arm (proxy.rs:662-672) | pre | 6 |
| 6 | **Fail-closed 503 (request_ctx None)** | `request_filter` fail-closed arm | pre | 6 |
| 7 | **Health 200 / HTTP→HTTPS redirect 301** | `request_filter` early arms | pre | 6 |
| 8 | Allow → upstream (MISS) | `response_filter` (proxy.rs:792) | post | 5 |
| 9 | Challenge-passed → upstream / **access-bypass passthrough** | `response_filter` | pre/post | 5 |
| 10 | Cache HIT | `write_cached_entry` (response_cache_integration.rs:12) | post | 5 |
| 11 | Transport error (timeout/circuit_breaker/502/503) | `fail_to_proxy` (proxy.rs:1039) | varies | 6 |

## Design Pattern

**Single source-of-truth snapshot on ctx + one shared injector (DRY + KISS).**

1. **One injector** — `inject_waf_observability_headers(resp, &WafHeaderValues)` in a new gateway
   module. The ONLY place that writes the 6 headers. Every egress path calls it. Clamps score,
   maps `None` rule_id → `none`, sanitizes CR/LF.
2. **Ctx snapshot** — `WafDecision` is a local in `request_filter`, unreachable from `response_filter`.
   Store a small `Option<WafDecisionMeta>` snapshot + `CacheStatus` on `GatewayCtx` the moment they
   are known (avoids cloning the heavy `DetectionResult`; Rule 7). Set it on EVERY outcome incl. the
   access-bypass fast-path (so passthrough never sees `None`).
3. **Egress fan-out** — every path in the inventory reads the snapshot (or builds inline values for
   pre-`inspect()` paths) and calls the injector.

### Egress Ordering Invariant (CRITICAL — resolves cache poisoning + FR-035 strip)

In `response_filter`, inject the 6 headers **as the final step — AFTER**:
   (a) `response_chain.apply_all` (blocklist strip), AND
   (b) the FR-035 `header_filter` block (proxy.rs:910-930, strips by name + PII value), AND
   (c) the `begin_upstream_cache_capture` block (proxy.rs:935-943).

Injecting last guarantees: FR-035 cannot strip the headers, and the cache snapshot (taken in (c))
NEVER contains per-request X-WAF-* → no stale replay to other clients on HIT.
**Belt-and-suspenders:** also add `"x-waf-"` to `header_filter` `preserve_prefixes` default, and
unconditionally strip `x-waf-*` inside `begin_upstream_cache_capture` (defense if injection ever moves).
WAF-decision paths (1-4) and error paths (5-7,11) build their own `ResponseHeader` and never run
FR-035/cache-capture, so they inject directly.

**Source:** `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md` §5, §7, §9
**Contract:** `analysis/docs/EN_waf_interop_contract_v2.3.md` §5 (lines 371–411), §2.7 (line 277)
**Builds on:** `plans/260529-1536-s3-waf-decision-classes/` (RT-05 deferred risk_score/rule_id wiring here)

## Phases

| Phase | Name | Status | Priority | Effort | Dependencies |
|-------|------|--------|----------|--------|--------------|
| 1 | [TDD Test Scaffold](./phase-01-tdd-test-scaffold.md) | completed | P1 | 3h | None |
| 2 | [Core Types + Injector Module](./phase-02-core-types-and-injector.md) | completed | P1 | 2h | Phase 1 |
| 3 | [Ctx Plumbing + Risk/Rule Wiring](./phase-03-ctx-plumbing-and-risk-wiring.md) | pending | P1 | 6h | Phase 2 |
| 4 | [Inject on WAF-Decision Paths](./phase-04-inject-waf-decision-paths.md) | pending | P1 | 3h | Phases 2,3 |
| 5 | [Inject on Passthrough + Cache-Hit](./phase-05-inject-passthrough-and-cache.md) | pending | P1 | 3h | Phases 2,3 |
| 6 | [Inject on Pre-Inspect + Error Paths](./phase-06-inject-transport-error-paths.md) | pending | P1 | 3h | Phases 2,3 |
| 7 | [Validation + Contract E2E](./phase-07-validation-and-contract-e2e.md) | pending | P1 | 3h | Phases 1-6 |

**Total estimated effort:** ~23h (3–3.5 days). Phase 6 raised to P1 (contract-mandatory error/pre-inspect paths); Phase 3 +2h for firm scorer wiring.

## Dependencies

- Phase 2 is the DRY core; everything depends on it.
- Phase 3 makes the snapshot reachable and (attempts to) wire risk_score.
- Phases 4, 5, 6 are **parallelizable** after Phase 3 (distinct egress paths, distinct functions).
- Phase 7 is the integration + contract-compliance gate over the FULL egress inventory.

## PR Strategy

One PR per phase. Phases 1–4 land block/challenge/body-block. Phase 5 completes allow/cache.
Phase 6 completes pre-inspect + error paths. Each phase runs `cargo check --workspace` + tests.

## Key Risks (carried into phase verification)

1. **Cache cross-request leak** — per-request X-WAF-* must never enter the cache set. Mitigated by
   the ordering invariant + mandatory `x-waf-*` strip in capture (Phase 5).
2. **FR-035 strip** — name- and PII-value-based stripping can remove X-WAF-*. Mitigated by inject-last
   + `preserve_prefixes` (Phase 5).
3. **risk_score wiring** — scorer not wired in `inspect()` today; Phase 3 wires it (validate decision).
   Phase 7 asserts a NON-zero score in a scored scenario (no hardcoded-0 false-green).
4. **Missed egress paths** — 6 paths were absent originally. Phase 1 + Phase 7 enumerate ALL 11 so
   coverage is test-enforced, not assumed.
5. **Audit correlation on ctx-None paths** — fallback UUID + minimal audit stub keeps it correlatable (Phase 6).
6. **mode fallback** — never hardcode `enforce`; derive from global default mode (Phase 3/5).

## Resolved Decisions (validate interview, 2026-05-30)

1. **Scorer wiring — WIRE NOW (in-scope).** Phase 3 threads the existing `Scorer`/`ScorerResult`
   into `WafDecision` so `X-WAF-Risk-Score` is real and `X-WAF-Rule-Id` uses `dominant_contributor()`.
2. **Audit correlation on ctx-None paths — WRITE MINIMAL AUDIT STUB.** Phase 6 generates a fallback
   UUID AND writes a minimal audit-log entry so `X-WAF-Request-Id` is always correlatable.
3. **Challenge-passed action — `allow`.** Phase 4 sets the snapshot action to `allow` on the
   valid-cookie branch; the upstream 200 reports `X-WAF-Action: allow`.
4. **rule_id exposure — EXPOSE AS-IS + Phase 7 namespace audit.** Emit internal rule ids directly;
   Phase 7 reviews the namespace for sensitive names before go-live.

## Open Questions

None — all four resolved above.
