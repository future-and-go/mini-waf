---
phase: 3
title: "PR-C: tx_velocity wiring — emit TX-SEQ / TX-WITHDRAW / TX-LIMIT signals"
status: pending
priority: P2
effort: "1d"
dependencies: [1]
pr_branch: "feat/audit-emitter-tx-velocity-wiring-issue-60-c"
loc_estimate: 750
red_team_applied: F-S-5, F-F-10
---

# Phase 3: tx_velocity wiring

## Overview

Wire `audit_emitter` vào tx_velocity classifier pipeline. Khi classifier breach (`TX-SEQ-001` login→OTP→deposit < 1500ms, `TX-WITHDRAW-001` ≥5 withdrawals/60s, `TX-LIMIT-001` ≥3 limit-change/5min) → 1 row vào `security_events`. Parallel với phase 02 (no shared files).

**Session-key sanitisation** (F-S-5): `detail.session_fp` = HMAC-SHA256 truncated 16 hex chars (key từ JWT secret env). Raw session key KHÔNG ship. Detail JSON cap 4KB.

## Requirements

### Functional
- `TxStore::record_with_audit` emit hook giữa classifier result và `tokio::spawn(submit)` (PR #62 anchor: line 198-202 of `recorder.rs`, verify on main)
- Mapping breach → (rule_id, rule_name, action, **sanitised JSON detail**) via `tx_velocity/audit_map.rs`
- Detail field: `{type, session_fp, breach_count, window_ms}` JSON. `session_fp` = `hex(hmac_sha256(jwt_secret, raw_session_key))[..16]` (F-S-5 — never ship raw session key); pipe qua `audit_emitter::sanitize::sanitize_detail` (phase 01 shared helper — serde_json + HTML escape + 4KB cap)
- Rule_id literals 3-segment grammar per BP6: `TX-SEQ-001`, `TX-WITHDRAW-001`, `TX-LIMIT-001` (regex contract test from phase 01 validates)

### Non-functional
- Coverage ≥ 90%
- BP1 applied
- Mock DB tests
- Behavioral test: breach trigger → row written within 2s

## Architecture

```
TxVelocityCheck::check (gateway request)
        │
        ├─ TxStore::record(session_key, event_type)
        │       │
        │       ├─ classify(events) → Vec<Breach>
        │       │
        │       └─ if !breaches.is_empty() →
        │             for breach in breaches:
        │                 AuditEmitter::emit(ctx, breach_to_audit(breach)…)
        │             tokio::spawn(submit_to_storage)
```

## Related Code Files

### Create
- `crates/waf-engine/src/checks/tx_velocity/audit_map.rs` — `breach_to_audit(&Breach) -> (rule_id, rule_name, action, detail)`
- `crates/waf-engine/tests/tx_velocity_emission.rs` — integration tests

### Modify
- `crates/waf-engine/src/checks/tx_velocity/check.rs` — verify access to `audit_emitter` từ check context
- `crates/waf-engine/src/checks/tx_velocity/recorder.rs` — `record_with_audit(...)` variant; emit hook giữa classifier output và `tokio::spawn(submit)`
- `crates/waf-engine/src/checks/tx_velocity/mod.rs` — re-export `audit_map`
- `crates/waf-engine/src/engine.rs` — propagate `Arc<AuditEmitter>` vào `tx_velocity_store` (phase 01 đã add `set_audit_emitter` API, phase 03 implement propagation)
- `docs/PRX-WAF-TechnicalGuide-EN.md` + `docs/PRX-WAF-TechnicalGuide-VI.md` — update rule_id reality (TX-* hiện thực sự emit; doc đã có table, nếu cell scope-status nói "logged" cần đổi sang "emitted to security_events") — F-F-10

### Delete
None.

## Implementation Steps (TDD)

### Step 1 — Write failing tests

1.1. `tests/tx_velocity_emission.rs`:
- `seq_breach_emits_tx_seq_001_row`
- `withdraw_breach_emits_tx_withdraw_001_row`
- `limit_change_breach_emits_tx_limit_001_row`
- `multi_breach_emits_one_row_per_rule_id`
- `disabled_emitter_short_circuits`
- `rate_limit_same_session_same_rule_id_collapses_per_window`
- `raw_session_key_never_appears_in_detail` (F-S-5 leak test)
- `session_fp_is_16_hex_chars_deterministic` (HMAC truncate)

1.2. Unit test cho `breach_to_audit` mapping function (3 variants × tests) + sanitisation:
- `detail_session_fp_truncated_16_hex`
- `detail_contains_no_pii_fields`
- `detail_truncated_at_4kb_boundary_safe`

1.3. Run Docker — **all FAIL**.

### Step 2 — Implement

2.1. `tx_velocity/audit_map.rs` — pure fn + constants:
```rust
pub const TX_SEQ_RULE_ID: &str = "TX-SEQ-001";
pub const TX_WITHDRAW_RULE_ID: &str = "TX-WITHDRAW-001";
pub const TX_LIMIT_RULE_ID: &str = "TX-LIMIT-001";
```

2.2. `recorder.rs::record_with_audit` — accept `Option<Arc<AuditEmitter>>` param hoặc store Arc trong struct (verify pattern hiện tại). Insert emit hook:
```rust
if !breaches.is_empty() {
    if let Some(emitter) = self.audit_emitter.as_ref() {
        for breach in &breaches {
            let (rid, rname, action, detail) = audit_map::breach_to_audit(breach);
            emitter.emit(&ctx, rid, rname, action, detail);
        }
    }
    tokio::spawn(submit_to_storage(breaches));
}
```

2.3. `engine.rs` — propagate audit_emitter vào `tx_velocity_store` qua existing setter pattern; verify storage struct allows Arc clone.

2.4. Tests pass.

### Step 3 — Refactor + verify

3.1. fmt/clippy clean.
3.2. Coverage ≥ 90%.
3.3. BP1 grep gate.
3.4. Squash, push, PR.

### Step 4 — PR draft body

```markdown
## Summary

Wires the `audit_emitter` into the tx_velocity classifier. When a session
exceeds the configured velocity (rapid login→OTP→deposit, frequent withdrawals,
or repeated limit-change requests), a row lands in `security_events` tagged
with the matching `TX-SEQ-*` / `TX-WITHDRAW-*` / `TX-LIMIT-*` rule_id.

## Rationale

Tech guide documents these rule_ids; until now they were classifier outputs
only, never persisted. The admin panel TX Velocity surface needed the bridge.

## Changes

- New `tx_velocity/audit_map.rs` — `breach_to_audit(&Breach)` + 3 constants
- `tx_velocity/recorder.rs` — `record_with_audit` variant; emit hook between
  classifier output and storage submit
- `engine.rs` — propagate `Arc<AuditEmitter>` to `tx_velocity_store`

## Tests

- Unit: 4 mapping tests
- Integration: 6 end-to-end tests (3 breach types + multi-breach + disabled-
  short-circuit + rate-limit-collapse)
- Mock DB + mock time for deterministic windows
- Coverage ≥ 90%
```

## Success Criteria

- [ ] All tests pass
- [ ] fmt/clippy clean
- [ ] Coverage ≥ 90%
- [ ] BP1 clean
- [ ] PR opened, CI green, NOT merged
- [ ] 1 squashed commit

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `recorder.rs` cấu trúc thay đổi sau PR #62 — line 198-202 anchor không còn match | Read main `recorder.rs` (521 LOC) trước khi patch; locate `if !breaches.is_empty()` callsite |
| Breach detail format ảnh hưởng FE drill-down | Document detail JSON schema trong PR description; FE coordinate qua issue #60 sub-thread |
| `audit_emitter` Arc clone thread-safety | Already Arc — no issue |
| Coverage gate fail cho time-based classifier branches | Use `tokio::time::pause` + advance ticker manually |

## Next Phase

Phase 04 (admin API endpoints) — blocked by phase 02 (needs `FeedStatusRegistry`).
