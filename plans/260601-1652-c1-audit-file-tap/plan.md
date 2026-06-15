---
title: "C1 Audit VictoriaLogs Enrichment — Contract §6 Fields + All-Decision Logging"
description: "Enrich VictoriaLogs audit payload with contract §6 fields (ts_ms, request_id, action, risk_score, mode) and log all 6 decision classes"
status: done
priority: P0
branch: "main"
tags: [interop, contract, benchmark, audit, c1, tdd]
blockedBy: []
blocks: [260527-1157-waf-interop-v23-critical-compliance]
created: "2026-06-01T10:03:45.984Z"
createdBy: "ck:plan"
source: skill
---

# C1 Audit VictoriaLogs Enrichment — Contract §6 Fields + All-Decision Logging

## Overview

Contract §6 requires audit events to carry specific field names (`ts_ms`, `request_id`, `action`, `risk_score`, `mode`). Currently, VictoriaLogs audit events use a different schema (`_time`, `req_id`, `event_type`) and only log block/challenge/rate_limit decisions — allow/timeout/circuit_breaker decisions are silently dropped.

**Strategy:** Enrich the existing VictoriaLogs audit pipeline. No file-tap needed — VictoriaLogs is the sole audit backend. Add contract fields to the VL JSON payload alongside existing fields (backward-compatible). Consolidate the 11 scattered `send_audit_event()` calls into a single call in `inspect()` to ensure all decisions are logged with accurate `risk_score`.

**Supersedes:** Original plan included a file-tap writer to `./waf_audit.log`. User decision: audit only needs VictoriaLogs. All file-tap phases removed.

## Design

```
AuditSender.send(event)
  └── VictoriaLogs path (existing, enriched)
        └── json!({_time, event_type, ..., ts_ms, request_id, action, risk_score, mode}) → BatchSender → HTTP POST
```

Key decisions:
1. **Add contract fields to VL payload** — `ts_ms`, `request_id`, `action`, `risk_score`, `mode`, `query` added alongside existing fields. Existing consumers (admin panel LogsQL queries) unaffected.
2. `AuditEvent` gains `risk_score: u8`, `mode: InteropMode`, `query: String`, and `contract_action: &'static str` fields
3. `contract_action` sourced from `WafAction::as_contract_str()` (all 6 contract values), NOT from `AuditEventType` (which collapses timeout/circuit_breaker/rate_limit into block). VL payload uses `action` (contract name) — no duplicate `contract_action` key.
4. **Single audit point in `inspect()`** — scattered `send_audit_event()` calls in `inspect_pipeline()` replaced by 1 call in `inspect()` after `risk_score` is set. This ensures all decisions (including allow, DDoS, community blocklist) are logged with accurate risk_score.
5. `send_audit_event()` handles `result: None` (allow decisions) with fallback values
6. **Timestamp consistency** — `AuditEvent.timestamp` set from inspection-start time (captured once in `inspect()`), not from `Utc::now()` at audit construction time. Avoids drift under load.
7. **Gateway stub events** — `emit_minimal_audit_stub()` (fail-closed 503 paths) uses `contract_action: "error"` to distinguish degraded events from real inspection results

## Phases

| Phase | Name | Status | Effort | Dep |
|-------|------|--------|--------|-----|
| 1 | [TDD: Contract-Enriched Audit Tests](./phase-01-tdd-contract-enriched-audit-tests.md) | Done | 1h | — |
| 2 | [Implement Contract Enrichment + All-Decision Logging](./phase-02-implement-contract-enrichment.md) | Done | 1.5h | 1 |

## Files Involved

| File | Action | Purpose |
|------|--------|---------|
| `crates/waf-engine/src/logging/audit_sender.rs` | Modify | Add contract fields to `AuditEvent`, enrich VL JSON payload |
| `crates/waf-engine/src/logging/mod.rs` | Verify | Confirm re-exports are correct |
| `crates/waf-engine/src/engine.rs` | Modify | Consolidate audit point in `inspect()`, populate new fields |
| `crates/waf-engine/tests/logging_audit_sender.rs` | Modify | Update `AuditEvent` construction sites with new fields |

## Dependencies

- **Blocks:** `260527-1157-waf-interop-v23-critical-compliance` (parent compliance plan)
- **No blockers** — `WafDecision` already has `risk_score: u8` and `mode: InteropMode` fields; `RequestCtx` has `query: String`

## Scope

- **H1 (audit field schema):** Add contract §6 fields to VictoriaLogs audit payload
- **H2 (all-decision logging):** Log all 6 decision classes (allow, block, challenge, rate_limit, timeout, circuit_breaker)
- **Consolidate audit point:** Single `send_audit_event()` in `inspect()` replaces 11 scattered calls in `inspect_pipeline()`

## Behavior Changes (Red-Team Noted)

- **New audit events for DDoS + community blocklist paths** — these paths never called `send_audit_event()` before. The single audit point in `inspect()` will now emit audit events for them. This is intentional (H2 coverage), but operators with VL alerting based on event_type counts should be aware.
- **Loss of per-check audit granularity** — previously, a custom-rule Allow/Log match fired its own audit event before the pipeline continued. After consolidation, only the final decision is audited. Trade-off accepted: contract cares about final decision, not intermediate matches.
- **Gateway fail-closed events** — `emit_minimal_audit_stub()` contract fields carry `contract_action: "error"` to distinguish from real inspection results.

## Out of Scope

- File-tap / JSONL file writer — user decision: not needed
- `audit_log_path` config field — not needed (no file output)
- M1 (separate peer_addr from client_ip) — separate gap
- VictoriaLogs format migration — existing fields preserved, new fields added alongside
- Deprecating `req_id` in favor of `request_id` — future cleanup
