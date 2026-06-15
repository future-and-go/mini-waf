---
phase: 2
title: "Implement Contract Enrichment + All-Decision Logging"
status: done
priority: P0
effort: "1.5h"
dependencies: [1]
---

# Phase 2: Implement Contract Enrichment + All-Decision Logging

## Overview

Wire contract §6 fields into the VictoriaLogs audit JSON payload. Consolidate the 11 scattered `send_audit_event()` calls into a single call in `inspect()` so all decisions — including allow — are logged with accurate `risk_score`.

## Requirements

- Functional: VL audit payload contains `ts_ms`, `request_id`, `action`, `risk_score`, `mode`, `query`. All 6 decision classes produce audit events.
- Non-functional: Zero behavioral change for existing VL consumers — existing fields preserved.
- Red-team: timestamp consistency (use inspection-start time), no duplicate `contract_action` key, `emit_minimal_audit_stub` uses `contract_action: "error"`.

## Architecture

**Before (11 scattered calls in `inspect_pipeline()`):**
```
inspect_pipeline()
  ├── ip_blacklist check → send_audit_event()
  ├── url_blacklist check → send_audit_event()
  ├── access gate → send_audit_event()
  ├── ... 8 more calls ...
  └── allow → (no audit event — H2 gap)
```

**After (single call in `inspect()`):**
```
inspect()
  ├── compute risk_score
  ├── decision = inspect_pipeline()
  ├── decision.risk_score = score
  └── send_audit_event(ctx, &decision)  ← ALL decisions, accurate risk_score
```

## Related Code Files

- Modify: `crates/waf-engine/src/logging/audit_sender.rs` — enrich `send()` JSON payload
- Modify: `crates/waf-engine/src/engine.rs` — consolidate audit point, populate new fields
- Modify: `crates/waf-engine/tests/logging_audit_sender.rs` — verify existing tests still pass

## Implementation Steps

### A. Enrich VL JSON Payload (`audit_sender.rs`)

1. **Add contract fields to the `json!()` macro** in `AuditSender::send()` (line 105-127):
   ```rust
   let payload = json!({
       // Existing fields (unchanged)
       "_time": event.timestamp.to_rfc3339(),
       "_msg": format!(...),
       "event_type": event.event_type.as_str(),
       "rule_name": event.rule_name,
       "rule_id": event.rule_id,
       "phase": event.phase,
       "client_ip": event.client_ip,
       "host": event.host,
       "method": event.method,
       "path": path,
       "tier": event.tier,
       "detail": event.detail,
       "req_id": event.req_id,
       "stream": "waf_audit",
       // Contract §6 fields (NEW)
       "ts_ms": event.timestamp.timestamp_millis(),
       "request_id": event.req_id,  // alias of req_id for contract
       "action": event.contract_action,  // granular 6-value mapping
       "risk_score": event.risk_score,
       "mode": event.mode.as_contract_str(),
       "query": event.query,
   });
   ```
   NOTE: `req_id` and `request_id` both present (backward compat + contract). No duplicate `contract_action` key — `action` is the contract field name. `event_type` (collapsed) and `action` (granular) coexist for different consumers.

2. **Extract `build_vl_payload()` for testability** (optional but recommended):
   - Move the payload construction into `fn build_vl_payload(event: &AuditEvent, path: String) -> serde_json::Value`
   - `send()` calls `build_vl_payload()` then `try_send()`
   - Unit tests call `build_vl_payload()` directly

### B. Consolidate Audit Point (`engine.rs`)

3. **Remove 11 `send_audit_event()` calls from `inspect_pipeline()`**:
   Delete calls at these approximate lines (verify exact positions):
   - Line 651 (ip_blacklist)
   - Line 666 (url_blacklist)
   - Line 689 (access gate)
   - Line 709 (crowdsec)
   - Line 733 (wasm plugin)
   - Line 744 (rhai plugin)
   - Line 757 (community)
   - Line 789 (owasp/rule match)
   - Line 804 (geo check)
   - Line 814 (cc check)
   - Line 824 (catch-all)

4. **Add single audit call in `inspect()`** after risk_score is set. Capture timestamp ONCE at inspection start for consistency (red-team MEDIUM-1):
   ```rust
   pub async fn inspect(&self, ctx: &mut RequestCtx) -> WafDecision {
       let inspect_time = chrono::Utc::now();
       let now_ms = inspect_time.timestamp_millis();
       let scorer_score = self.scorer.score(ctx, None, &[], None, now_ms)
           .await.map_or(0, |r| r.score);
       let mut decision = self.inspect_pipeline(ctx).await;
       decision.risk_score = scorer_score.min(100);
       self.send_audit_event(ctx, &decision, inspect_time);
       decision
   }
   ```

5. **Fix `send_audit_event()` to handle `result: None`** (allow decisions) and accept inspection timestamp:
   Current code at line 996-998 early-returns on `None` result. Replace:
   ```rust
   fn send_audit_event(&self, ctx: &RequestCtx, decision: &WafDecision,
                       timestamp: chrono::DateTime<chrono::Utc>) {
       let Some(sender) = self.audit_sender.get() else { return; };

       let (rule_name, rule_id, phase, detail) = match &decision.result {
           Some(r) => (r.rule_name.clone(), r.rule_id.clone(),
                       Some(r.phase.to_string()), Some(r.detail.clone())),
           None => (String::new(), None, None, None),
       };

       #[allow(deprecated)]
       let event_type = match &decision.action {
           WafAction::Block { .. } | WafAction::RateLimit { .. }
           | WafAction::Timeout { .. } | WafAction::CircuitBreaker { .. } => AuditEventType::Block,
           WafAction::Allow => AuditEventType::Allow,
           WafAction::LogOnly => AuditEventType::LogOnly,
           WafAction::Redirect { .. } | WafAction::Challenge => AuditEventType::Challenge,
       };

       let event = AuditEvent {
           timestamp,  // inspection-start time, not construction time
           event_type,
           rule_name,
           rule_id,
           phase,
           client_ip: ctx.client_ip.to_string(),
           host: ctx.host.clone(),
           method: ctx.method.clone(),
           path: ctx.path.clone(),
           query: ctx.query.clone(),
           tier: Some(format!("{:?}", ctx.tier)),
           detail,
           req_id: Some(ctx.req_id.clone()),
           risk_score: decision.risk_score,
           mode: decision.mode,
           contract_action: decision.action.as_contract_str(),
       };
       sender.send(event);
   }
   ```

6. **Update `emit_minimal_audit_stub()` fields** (line 478):
   Add `query: String::new()`, `risk_score: 0`, `mode: InteropMode::Enforce`, `contract_action: "error"`.
   Use `"error"` (not `"allow"`) to distinguish degraded gateway stub events from real inspection results (red-team CRITICAL-2).

### C. Verify

7. `cargo check -p waf-engine` — zero errors
8. `cargo check -p prx-waf` — binary compiles
9. `cargo test -p waf-engine` — all tests pass (Phase 1 + existing)
10. `cargo fmt --all`

## Success Criteria

- [ ] VL JSON payload contains contract §6 fields: `ts_ms`, `request_id`, `action`, `risk_score`, `mode`, `query`
- [ ] No duplicate `contract_action` key — `action` is the contract field
- [ ] Existing VL fields unchanged (`_time`, `event_type`, `req_id`, `stream`, etc.)
- [ ] `send_audit_event()` uses inspection-start timestamp (not construction time)
- [ ] Scattered `send_audit_event()` calls removed from `inspect_pipeline()`
- [ ] 1 `send_audit_event()` call added in `inspect()` after `risk_score` set
- [ ] `send_audit_event()` handles `result: None` with fallback values
- [ ] All 6 decision classes produce audit events (allow, block, challenge, rate_limit, timeout, circuit_breaker)
- [ ] `emit_minimal_audit_stub()` updated with new fields, uses `contract_action: "error"`
- [ ] All Phase 1 tests pass
- [ ] All existing tests in `tests/logging_audit_sender.rs` pass
- [ ] `cargo check --workspace` clean
- [ ] `cargo fmt --all` clean

## Risk Assessment

- **Scattered call removal is high-impact** — must verify no caller depends on per-check audit events arriving before `inspect()` returns. Current consumers (VL LogsQL queries, admin panel) query by `event_type`/`host`/`client_ip` — none depend on intra-pipeline timing.
- `report_community_signal()` also called from `inspect_pipeline()` — those STAY (separate from audit). Only `send_audit_event()` calls move.
- Adding fields to `AuditEvent` is backward-compatible for VL ingestion (JSON is schema-less).
- `action` (granular, 6 values) vs `event_type` (collapsed, 5 values): both in payload. Different consumers choose which to query.
- **DDoS + community blocklist paths** never had `send_audit_event()` calls — single audit point in `inspect()` gives them audit events for the first time. Intentional H2 coverage expansion.
- **Custom-rule Allow/Log match** previously fired its own audit event mid-pipeline. After consolidation, only final decision is audited. Accepted tradeoff: contract cares about final outcome.
