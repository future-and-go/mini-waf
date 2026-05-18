---
phase: 3
title: "FR-012 tx_velocity breach → security_events (red-team patched)"
status: pending
priority: P0
effort: "7h"
dependencies: [1]
---

# Phase 3: FR-012 tx_velocity event emission

## Overview

Wire breach signals từ tx_velocity classifiers → `audit_emitter.emit()`. Sub-issue #3 frontend cần filter `?rule_id=TX-SEQ` / `TX-WITHDRAW` / `TX-LIMIT` — rows hiện không tồn tại. Entry point thật ở `recorder.rs:201` (NOT `check::evaluate` — function đó luôn return None per red-team F3.1).

## Requirements

**Functional:**
- Mỗi `TxBreach` (hoặc tương đương) return từ evaluate → 1 emit.
- Mapping cố định:
  | Breach type | rule_id | rule_name |
  |---|---|---|
  | Sequence too fast (Login→OTP→Deposit interval < min_human_ms) | `TX-SEQ-001` | tx_sequence |
  | Withdrawal velocity exceeded | `TX-WITHDRAW-001` | tx_withdraw |
  | Limit-change storm | `TX-LIMIT-001` | tx_limit |
- `action = "block"` cho cả 3 (breach luôn dẫn tới block per FR-012 spec).
- `detail` JSON chứa: `interval_ms`, `window_ms`, `count`, `endpoint_sequence` (tuỳ breach).

**Non-functional:**
- Emit không block hot path (vẫn dùng `try_send` qua emitter).
- Mapping function pure, exhaustive over breach enum.

## Architecture

Entry point (red-team F3.1 fix): **`tx_velocity::check::evaluate` KHÔNG tồn tại** — `TxVelocityCheck::check()` luôn return `None`. Breach phát hiện trong `crates/waf-engine/src/checks/tx_velocity/recorder.rs:201` ở chỗ `classifiers.iter().filter_map(|c| c.evaluate(&snap, now_ms, &cfg))` — đây là chỗ emit phải hook.

```rust
// recorder.rs:201 (after classifier produces signal)
for sig in classifiers.iter().filter_map(|c| c.evaluate(&snap, now_ms, &cfg)) {
    let (rule_id, detail) = audit_map::signal_to_rule_id(&sig);
    // NEW:
    if let Some(emitter) = &self.audit_emitter {
        let ctx = audit_ctx_from_session(&session_key);  // path/host derived from snapshot
        emitter.emit(&ctx, rule_id, "block", &detail);
    }
    // existing: route signal to aggregator
    aggregator.record_signal(sig);
}
```

**Decision** (red-team F3.2/F3.3 fix): `Arc<AuditEmitter>` inject vào **`TxStore::new(cfg, audit_emitter)`** — `Check::new` wrap rồi pass-through. Breaks public TxStore signature → cần cross-plan comment tới owner của plan `260504-1632-fr-012-transaction-velocity` (Phase 0 handles).

**`ctx` materialization**: snapshot lưu `client_ip` và `host_code` cùng `SessionKey`. Nếu không có sẵn, Phase 0 walk note. Worst case: thêm 2 field vào `SessionKey` hoặc snapshot — backward-compat default empty string.

## Related Code Files

- Read: `crates/waf-engine/src/checks/tx_velocity/check.rs` (verify Check impl trả None)
- Read: `crates/waf-engine/src/checks/tx_velocity/recorder.rs:180-220` (classifier signal emit chain — line 201)
- Read: `crates/waf-engine/src/checks/tx_velocity/{classifiers,classifier}.rs` (signal enum)
- Read: `plans/260504-1632-fr-012-transaction-velocity/phase-02-classifiers-signal-emission.md` (cross-ref existing)
- Create: `crates/waf-engine/src/checks/tx_velocity/audit_map.rs` (~70 lines — signal variants)
- Modify: `crates/waf-engine/src/checks/tx_velocity/recorder.rs` — thêm `audit_emitter: Option<Arc<AuditEmitter>>` field, emit ngay sau classifier produces signal
- Modify: `crates/waf-engine/src/checks/tx_velocity/check.rs` — pass-through emitter từ Check::new → TxStore::new
- Modify: `crates/waf-engine/src/checks/tx_velocity/mod.rs` — re-export audit_map
- Create: `crates/waf-engine/tests/tx_velocity_audit_emission.rs` (~150 lines)

## Implementation Steps

1. **Map breach → rule_id** trong `audit_map.rs`:
   - Match enum variants, return `(&'static str, &'static str)`.
   - Helper `build_detail(&TxBreach) -> String` (JSON via `serde_json::json!`).
2. **Inject emitter into Check**:
   - `Check::new(...)` thêm param `emitter: Arc<AuditEmitter>`.
   - Field `emitter: Arc<AuditEmitter>`.
   - Update call sites (1-2 trong `engine.rs`).
3. **evaluate() patch**:
   - Sau khi classifier return Some(breach), build detail JSON, call `emitter.emit(...)`.
   - Giữ semantic cũ: vẫn return Some(breach) cho risk pipeline.
4. **Integration test** (`tests/tx_velocity_audit_emission.rs`):
   - 3 test case: Sequence breach, Withdraw breach, Limit breach.
   - Mỗi case: setup postgres testcontainer, gọi engine với request sequence trigger breach, assert row `security_events` với expected rule_id + detail.
5. **Verify no regression**:
   - `cargo test -p waf-engine tx_velocity` (4 existing test file).
6. **Bench check**: bench cũ `tx_velocity_bench` không regression > 5%.

## Success Criteria

- [ ] 3 unit tests cho audit_map pass.
- [ ] 3 integration tests cho 3 breach type pass.
- [ ] Existing 4 tx_velocity test file đều xanh.
- [ ] Coverage ≥ 90% trên `audit_map.rs`.
- [ ] Bench p99 latency không regress > 5%.
- [ ] Update `plans/260504-1632-fr-012-transaction-velocity/plan.md` — note "audit emission added in plan 260518-1706".

## Risk Assessment

- **Existing tx_velocity plan đã `complete`**: phase này là addition, owner cũ không phải refactor. Cross-plan note để tránh nhầm.
- **Breach trùng nhiều lần per session**: rate limiter ở phase 1 handle (1 emit/60s/IP/rule_id).
- **`detail` JSON size lớn**: cap < 1KB. Test với worst-case sequence (5 endpoints).
- **Race emit vs risk score raise**: emit là fire-and-forget; risk score raise xảy ra sync. OK — không cần atomic.

## Notes

- Detail JSON example cho TX-SEQ-001:
  ```json
  {"interval_ms": 1230, "min_human_ms": 5000, "sequence": ["/login", "/otp", "/deposit"], "session_id": "..."}
  ```
- Helper `build_detail` không leak PII (no full session token, chỉ truncated/hash).
