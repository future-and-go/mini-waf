---
title: "WAF Interop Contract v2.3 — Critical Gap Compliance"
description: "Implement all CRITICAL interop contract gaps to make the WAF benchmark-compatible without breaking existing functionality"
status: pending
priority: P1
branch: "main"
tags: [interop, contract, benchmark, hackathon]
blockedBy: []
blocks: []
created: "2026-05-27T05:01:42.100Z"
createdBy: "ck:plan"
source: skill
---

# WAF Interop Contract v2.3 — Critical Gap Compliance

## Overview

Make the WAF benchmark-compatible with interop contract v2.3 by closing 6 CRITICAL gaps. Core strategy: **additive changes only** — new types, new modules, new filters. Existing detection pipeline untouched except for log_only semantic fix in the engine's decision-output path.

**Source:** `plans/reports/contract-gap-analysis-260527-1133-waf-interop-v23-report.md`
**Contract:** `analysis/docs/EN_waf_interop_contract_v2.3.md`

## Design Principles

1. **Non-breaking**: Existing `WafAction` variants preserved. New variants added. Existing API endpoints untouched.
2. **Strategy pattern**: Per-feature/per-policy mode control via `ModeRegistry` (ArcSwap) — decoupled from HostConfig.
3. **Trait-based extension**: New `ResponseFilter` impl for headers; new `AuditWriter` trait for JSONL; new Axum route group for control.
4. **VictoriaLogs-primary audit**: VictoriaLogs remains the primary logging system. JSONL file writer is a secondary interop-contract output — additive only, no changes to VictoriaLogs pipeline.
5. **TDD**: Each phase writes tests first, implements second, validates third.

## Architecture Impact

```
waf-common  → Add: WafAction::{RateLimit,Timeout,CircuitBreaker}, WafDecision::{risk_score,mode,rule_id}
              Add: InteropMode enum, ModeOverride types, FeatureId/PolicyId
waf-engine  → Fix: log_only preserves intended action + sets mode field
              Add: ModeRegistry (ArcSwap<ModeState>)
              Add: AuditWriter trait + JsonlAuditWriter impl
gateway     → Add: WafObservabilityHeaderFilter (ResponseFilter impl)
              Modify: FilterCtx to carry WafDecision + cache status
waf-api     → Add: /__waf_control/* route group with benchmark-secret auth
prx-waf     → Add: config auto-discovery, wrapper script for ./waf run
```

## Phases

| Phase | Name | Status | Priority | Effort | Dependencies |
|-------|------|--------|----------|--------|--------------|
| 1 | [Core Type System Refactor (§3 + log_only)](./phase-01-core-type-system-refactor-3-log-only.md) | Pending | P1 | 1-2d | None |
| 2 | [Response Observability Headers (§5)](./phase-02-response-observability-headers-5.md) | Pending | P1 | 1d | Phase 1 |
| 3 | [JSONL Interop Audit Writer (§6)](./phase-03-jsonl-audit-log-writer-6.md) | Pending | P1 | 1d | Phase 1 |
| 4 | [Control Interface (§2)](./phase-04-control-interface-2.md) | Pending | P1 | 1-2d | Phase 1 |
| 5 | [Binary Startup Contract (§8)](./phase-05-binary-startup-contract-8.md) | Pending | P2 | 0.5d | Phase 3 |
| 6 | [Integration Testing & Regression](./phase-06-integration-testing-regression.md) | Pending | P1 | 1d | Phases 1-5 |

**Total estimated effort:** 5-7 days

## Dependencies

- Phase 2 + 3 can run in **parallel** after Phase 1 completes (independent outputs: headers vs file)
- Phase 4 depends on Phase 1 (needs ModeRegistry for set_profile)
- Phase 5 is lowest coupling — only depends on JSONL log path from Phase 3
- Phase 6 is the integration gate — validates everything together

## Red-Team Findings Applied

3 CRITICAL, 4 HIGH, 4 MEDIUM findings from adversarial review. All addressed in phase files.

| ID | Severity | Fix Applied |
|----|----------|-------------|
| RT-01 | CRITICAL | Add `socket_ip: IpAddr` to RequestCtx (Phase 1). Use for JSONL `ip` field |
| RT-02 | CRITICAL | Write interop fields to `ctx.request_ctx` (GatewayCtx) directly, not local clone (Phase 2) |
| RT-03 | CRITICAL | Dual header injection: `inject_interop_headers()` in both `write_waf_decision` AND ResponseFilter (Phase 2) |
| RT-04 | HIGH | Keep `is_allowed()` as deprecated wrapper (Phase 1) |
| RT-05 | HIGH | Remove `x-waf-version` from default blocklist (Phase 2) |
| RT-06 | HIGH | `set_all()` clears override maps (Phase 4) |
| RT-07 | HIGH | Grep-verify actual log_only_mode branch count before refactoring (Phase 1) |
| RT-08 | MEDIUM | `RuleAction::Log` maps to `WafAction::Allow` instead of `LogOnly` (Phase 1) |
| RT-09 | MEDIUM | Remove `const` from WafDecision constructors (Phase 1) |
| RT-10 | MEDIUM | Wire risk scorer's actor accumulator to `WafDecision.risk_score` (Phase 1) |
| RT-11 | MEDIUM | `as_contract_str()` produces plain strings; serde internally-tagged format preserved (Phase 1) |

Full report: `plans/reports/code-reviewer-260527-1208-red-team-interop-v23-compliance-plan-review-report.md`

## User Decisions (Validation Interview)

| Question | Decision | Impact |
|----------|----------|--------|
| CircuitBreaker scope | Implement real CB via FR-039 | Wire upstream health into WafAction::CircuitBreaker |
| JSONL writer toggle | Config toggle `[interop] audit_log_enabled` | Default true; can disable for non-benchmark deployments |
| ModeRegistry vs HostConfig | Coexist with fallback | ModeRegistry priority, HostConfig.log_only_mode as fallback |
| access_bypass observability | Inject minimal headers + audit | All requests get X-WAF-* headers, even bypassed ones |
| Logging system primary | VictoriaLogs stays primary | JSONL is secondary interop-contract output only; VictoriaLogs pipeline unchanged |

## Known Limitations (Deferred)

- **§4 Challenge format**: Existing PoW renderer may not match contract Format A/B exactly. Scored as HIGH, not CRITICAL. Deferred to follow-up.
- **§10 Loopback aliasing**: Rate-limiter currently keys on `client_ip` not `socket_ip`. Must verify after Phase 1 adds `socket_ip`.
- **§2.7 Multi-policy mode resolution**: When request matches multiple policies with different modes, the last phase's mode wins (most-specific-last). Documented in Phase 4.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| WafAction enum change breaks deserialization of stored data | Add `#[serde(alias)]` for backward compat; PostgreSQL stores event_type as string |
| log_only refactor changes detection behavior | TDD: existing engine tests must pass unchanged |
| WafDecision not reachable in response_filter | RT-02 fix: populate GatewayCtx directly + inject in write_waf_decision |
| Headers missing on blocked responses | RT-03 fix: dual injection in write_waf_decision AND ResponseFilter |
| Control endpoints expose attack surface | X-Benchmark-Secret header guard + admin-only binding |
| Binary rename breaks CI/Docker/systemd | Wrapper script approach — no rename of actual binary |
