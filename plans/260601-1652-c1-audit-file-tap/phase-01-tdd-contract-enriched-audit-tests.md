---
phase: 1
title: "TDD: Contract-Enriched Audit Tests"
status: done
priority: P0
effort: "1h"
dependencies: []
---

# Phase 1: TDD: Contract-Enriched Audit Tests

## Overview

Write tests that verify: (a) the VictoriaLogs audit payload includes contract §6 fields, and (b) all 6 decision classes produce audit events. Tests define the exact field expectations before implementation.

## Requirements

- Functional: Tests validate contract fields in VL JSON payload + all-decision audit coverage
- Non-functional: Tests run in `#[cfg(test)]` within `audit_sender.rs` and integration test file

## Architecture

The enriched VL payload adds these contract fields alongside existing ones:
```json
{
  "_time": "2026-...",
  "event_type": "block",
  "req_id": "uuid",
  "ts_ms": 1717200000000,
  "request_id": "uuid",
  "action": "block",
  "risk_score": 85,
  "mode": "enforce",
  "query": "id=1&sort=name"
}
```
Note: `action` (granular, 6 values from `WafAction::as_contract_str()`) and `event_type` (collapsed, 5 values from `AuditEventType::as_str()`) coexist. No separate `contract_action` key.

New `AuditEvent` fields needed (stub with defaults so tests compile):
| Field | Type | Source |
|---|---|---|
| `risk_score` | `u8` | `WafDecision.risk_score` |
| `mode` | `InteropMode` | `WafDecision.mode` |
| `query` | `String` | `RequestCtx.query` |
| `contract_action` | `&'static str` | `WafAction::as_contract_str()` |

## Related Code Files

- Modify: `crates/waf-engine/src/logging/audit_sender.rs` (add fields to `AuditEvent`, add tests)
- Modify: `crates/waf-engine/tests/logging_audit_sender.rs` (update `make_event()` + inline constructions)

## Implementation Steps

1. **Add new fields to `AuditEvent`** (`audit_sender.rs:53-66`) as stubs with sensible defaults so tests compile:
   ```rust
   pub struct AuditEvent {
       // ... existing fields ...
       pub risk_score: u8,
       pub mode: waf_common::types::InteropMode,
       pub query: String,
       pub contract_action: &'static str,
   }
   ```

2. **Update ALL `AuditEvent` construction sites** with default values (4 sites):
   - `engine.rs:1011` — `send_audit_event()`: `risk_score: 0, mode: InteropMode::Enforce, query: String::new(), contract_action: "allow"`
   - `engine.rs:478` — `emit_minimal_audit_stub()`: same defaults
   - `tests/logging_audit_sender.rs:30` — `make_event()`: same defaults
   - `tests/logging_audit_sender.rs:173` — inline: same defaults

3. **Test `vl_payload_includes_contract_fields`** (in `audit_sender.rs` unit tests):
   - This test requires access to the `json!()` payload. Two approaches:
     - (a) Extract payload construction into a testable function `fn build_vl_payload(event: &AuditEvent) -> serde_json::Value`
     - (b) Use wiremock to capture the POST body and parse it
   - Preferred: (a) — extract `build_vl_payload()` as a private helper, test directly
   - Assert the returned `Value` contains: `ts_ms` (i64), `request_id` (string), `action` (string), `risk_score` (u8), `mode` (string), `query` (string)
   - Assert NO duplicate `contract_action` key — `action` IS the contract field
   - Also assert existing fields still present: `_time`, `event_type`, `req_id`, `stream`

4. **Test `contract_action_uses_all_six_values`**:
   - Verify `WafAction::as_contract_str()` returns distinct values for all 6 action types
   - `Block{..}` → `"block"`, `Allow` → `"allow"`, `Challenge` → `"challenge"`, `RateLimit{..}` → `"rate_limit"`, `Timeout{..}` → `"timeout"`, `CircuitBreaker{..}` → `"circuit_breaker"`
   - NOTE: This test already exists in `waf-common/tests/types_decisions.rs:248` — add a cross-reference comment but don't duplicate. Focus this test on verifying `contract_action` flows into the VL payload correctly.

5. **Test `vl_payload_ts_ms_is_epoch_milliseconds`**:
   - Create `AuditEvent` with known timestamp (e.g. 2026-01-01T00:00:00Z)
   - Build payload, assert `ts_ms` == `1767225600000`
   - Also assert `_time` (RFC3339) and `ts_ms` (epoch ms) represent the same instant — timestamp consistency

6. **Test `vl_payload_risk_score_and_mode_propagate`**:
   - Create event with `risk_score: 75`, `mode: InteropMode::LogOnly`, `contract_action: "rate_limit"`
   - Build payload, assert `risk_score == 75`, `mode == "log_only"`, `action == "rate_limit"`

7. **Test `vl_payload_query_appended_to_path`**:
   - Event with `path: "/api/users"`, `query: "id=1&sort=name"`
   - Build payload, assert `query == "id=1&sort=name"`
   - Also test empty query → `query` field is empty string (not absent)

8. Run `cargo check -p waf-engine` — must compile. Tests pass against stub defaults.

## Success Criteria

- [ ] `AuditEvent` struct has 4 new fields: `risk_score`, `mode`, `query`, `contract_action`
- [ ] All 4 construction sites updated with defaults (compiles cleanly)
- [ ] 4-5 test functions written covering: contract fields in payload, action mapping, timestamp millis, risk_score+mode propagation, query field
- [ ] `cargo check -p waf-engine` passes
- [ ] `cargo check -p prx-waf` passes (engine.rs construction sites fixed)
- [ ] Existing tests in `tests/logging_audit_sender.rs` still pass

## Risk Assessment

- Adding fields to `AuditEvent` breaks 4 construction sites — all listed with exact line numbers
- `build_vl_payload()` extraction is a minor refactor of `send()` — must not change runtime behavior
