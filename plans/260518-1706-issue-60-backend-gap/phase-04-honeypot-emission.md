---
phase: 4
title: "FR-028 honeypot hit → security_events (BLOCKED — chờ reviewer ack rule_id)"
status: pending
priority: P0
effort: "2h"
dependencies: [1, "reviewer-ack-honeypot-rule-id"]
---

<!-- Updated: Validation Session 1 - V2 lock: NO default fallback. Phase 4 blocked until @protonmns confirms rule_id prefix via issue #60 comment. -->


# Phase 4: FR-028 honeypot event emission

## Overview

`canary.rs::check_and_ban()` hiện chỉ `tracing::warn!()` + bump risk score. Sub-issue #5 frontend cần filter `?rule_id=HONEY-*` — không có row nào hôm nay. Phase này thêm 1 lần emit per honeypot hit.

## Requirements

**Functional:**
- Mỗi honeypot path hit → 1 row `security_events` với `rule_id = "HONEY-001"` (chốt chính thức ở Phase 0; default này nếu reviewer im).
- `rule_name = "canary_honeypot"`.
- `action = "block"` (canary luôn ban).
- `detail` JSON: `{"path": "<triggered_path>"}` (cap 256 chars, không leak ngoài request path đã có sẵn).

**Non-functional:**
- Rate-limit qua emitter — 1 emit per (IP, rule_id) per 60s. Lý do: bot quét sẽ hit cùng IP nhiều honeypot path trong burst; chỉ cần 1 entry là đủ alert.
- Wait — multiple paths same IP nên cùng rule_id sẽ bị suppress. Đề xuất: include path trong rule_id để tách (`HONEY-<sha8(path)>-001`)? **Decision**: KHÔNG. Honeypot semantics: "IP X đã hit honeypot" là sự kiện; path nào trong detail. Suppress duplicate trong 60s OK.

## Architecture

Entry point đúng (red-team F4.1 fix): hook tại **caller** `crates/waf-engine/src/risk/scorer.rs:178`, KHÔNG modify canary.rs. `check_and_ban` giữ pure signature `(path, ip, now_ms) -> bool` — không cần `&RequestCtx`.

**Red-team F4.1 detail**: `check_and_ban` trả **`bool`** (KHÔNG enum `CanaryDecision`). Verified `risk/canary.rs:96`: `pub fn check_and_ban(&self, path: &str, ip: IpAddr, now_ms: i64) -> bool`. Caller duy nhất ở `crates/waf-engine/src/risk/scorer.rs:178`:

```rust
// scorer.rs:178 (existing)
if let Some(ref canary) = self.canary
    && cfg.canary.enabled
    && canary.check_and_ban(&ctx.path, ctx.client_ip, now_ms)
{
    // existing: force_max risk score, ban_table.insert, etc.
    // NEW (this phase):
    let detail = serde_json::json!({"path": truncate(&ctx.path, 256)}).to_string();
    if let Some(emitter) = &self.audit_emitter {
        emitter.emit(ctx, HONEYPOT_RULE_ID, "block", &detail);
    }
}
```

**Decision**: hook tại `RiskScorer` (đã có `&ctx`), KHÔNG ở engine.rs. Inject `audit_emitter: Option<Arc<AuditEmitter>>` vào `RiskScorer` constructor.

`HONEYPOT_RULE_ID` là `const &'static str` đặt một chỗ duy nhất trong `crates/waf-engine/src/risk/canary.rs` (hoặc `risk/audit_constants.rs`) — Phase 0 chốt value sau khi reviewer ack. **Không** dùng 24h timeout default (red-team F0.1 fix). Nếu reviewer im, escalate trong PR — KHÔNG silent commit `HONEY-001` vào historical rows.

Detail JSON: dùng `serde_json::json!` (red-team F4.3 fix), KHÔNG hand-rolled.

## Related Code Files

- Read: `crates/waf-engine/src/risk/canary.rs:96` (`fn check_and_ban -> bool`)
- Read: `crates/waf-engine/src/risk/scorer.rs:170-200` (caller — single insertion point)
- Modify: `crates/waf-engine/src/risk/scorer.rs` — inject `audit_emitter: Option<Arc<AuditEmitter>>` field + emit 4-6 dòng sau `check_and_ban` returns true
- Modify: `crates/waf-engine/src/risk/canary.rs` — thêm `pub const HONEYPOT_RULE_ID: &str = "..."` (single source of truth)
- Create: `crates/waf-engine/tests/canary_audit_emission.rs` (~80 lines)
- Reference: Phase 0 quyết định honeypot rule_id prefix (NO timeout default)

## Implementation Steps

1. **Decision check**: confirm rule_id prefix từ Phase 0 (`HONEY-001` default).
2. **Find canary invocation** trong `engine.rs` (grep `check_and_ban\|CanaryLayer`).
3. **Add emit branch**:
   - Sau canary returns Block, build detail JSON, gọi `self.emitter.emit(ctx, "HONEY-001", "block", &detail)`.
   - Helper `truncate_path(path: &str, max: usize) -> Cow<str>` (avoid alloc nếu path short).
4. **Integration test** (`tests/canary_audit_emission.rs`):
   - Setup postgres testcontainer + engine + honeypot config có path `/.env`.
   - Send request to `/.env` → assert 1 row `security_events` rule_id=HONEY-001 action=block detail JSON path=`/.env`.
   - Send 2 request cùng IP < 60s → assert 1 row (rate limiter).
   - Send request to non-honeypot path → assert 0 row HONEY-* (negative test).
5. **No regression check**: `cargo test -p waf-engine canary` (existing test files).

## Success Criteria

- [ ] 3 integration tests pass.
- [ ] Existing canary tests (test_canary, risk_scorer_decision_matrix nếu có) đều xanh.
- [ ] `engine.rs` thay đổi ≤ 10 dòng (surgical).
- [ ] Detail JSON < 300 bytes typical.
- [ ] FE có thể `GET /api/security-events?rule_id=HONEY-001` và trả về row.

## Risk Assessment

- **Path injection trong detail**: `serde_json::json!` an toàn — escape automatic.
- **Bot quét 100 honeypot path × cùng IP**: rate limiter suppress xuống còn 1 row/window. **Red-team F4.2 trade-off**: forensic loss — chỉ ghi PATH đầu tiên. Mitigation: thêm metric counter `honeypot.suppressed_paths` cho operator xem true count, plus phase 7 multi-path test verify 1 row + counter ≥ N.
- **F4.4 race**: scorer `force_max` + `ban_table.insert` chạy ngay sau emit; subsequent burst hits bị ban → emit không chạy. Document trong commit: "honeypot count rows = unique IP hits per window, not total path probes".
- **Honeypot config thay đổi runtime**: không ảnh hưởng emit (emit chỉ chạy khi `check_and_ban` return true).

## Notes

- Nếu Phase 0 chốt prefix khác (`HONEYPOT-001` hoặc `CANARY-001`) → update constant ở engine.rs + test expectations.
- Phase này KHÔNG modify canary.rs (giữ pure, KISS).
