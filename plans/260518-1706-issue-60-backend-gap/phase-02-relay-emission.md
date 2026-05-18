---
phase: 2
title: "FR-007 relay signal → security_events (red-team patched)"
status: pending
priority: P0
effort: "5h"
dependencies: [1]
---

# Phase 2: FR-007 relay event emission

## Overview

Wire `RelayRegistry` signals → `audit_emitter.emit()` để các loại relay/proxy detection xuất hiện trong `security_events` với rule_id chuẩn hóa frontend query được.

## Requirements

**Functional:**
- Mỗi `Signal` non-empty từ `RelayDetector::evaluate(peer_ip, headers) -> ClientIdentity { signals, .. }` ở `gateway/src/proxy.rs:432` → 1 lần `emit()` với rule_id + detail JSON.
- Mapping (Signal enum verbatim từ `crates/waf-engine/src/relay/signal.rs:30-47` — red-team F2.2 fix):
  | Signal variant | rule_id | rule_name |
  |---|---|---|
  | `XffSpoofPrivate` | `BOT-XFF-SPOOF-PRIVATE-001` | xff_validator |
  | `XffMalformed` | `BOT-XFF-MALFORMED-001` | xff_validator |
  | `XffTooLong` | `BOT-XFF-TOOLONG-001` | xff_validator |
  | `ExcessiveHopDepth(u8)` | `BOT-RELAY-HOPDEPTH-001` (depth trong `detail`) | proxy_chain |
  | `AsnDatacenter { asn, org }` | `BOT-RELAY-ASN-DC-001` (asn/org trong `detail`) | asn_classifier |
  | `AsnResidential` | `BOT-RELAY-ASN-RESI-001` | asn_classifier |
  | `AsnUnknown` | `BOT-RELAY-ASN-UNKNOWN-001` | asn_classifier |
  | `TorExit` | `BOT-RELAY-TOR-001` | tor_exit |
- **Action = `"log_only"`** cho mọi relay-signal emit. Lý do (red-team F2.3): tại access phase entry point, engine WAF decision chưa chạy → không có `WafAction` để map. Signal chỉ raise risk score; rule engine downstream sẽ tự log `block/challenge` riêng nếu hit rule khác. Audit row của relay layer luôn là `log_only` chỉ chứng minh signal đã được detect.

**Non-functional:**
- Mapping function pure (no I/O), `#[inline]`.
- Không emit trùng signal trong 1 request (1 evaluate call → max 1 emit per signal variant).

## Architecture

Entry point: `RelayDetector::evaluate` được gọi tại **`crates/gateway/src/proxy.rs:432`** (verified red-team F2.1, không phải `engine.rs`). Tại điểm này `ClientIdentity { signals: Vec<Signal>, .. }` được materialize → đây là chỗ emit.

Insertion: thread `Arc<AuditEmitter>` vào gateway proxy ctx (cùng pattern với `relay_detector: Option<Arc<RelayDetector>>` ở `proxy.rs:84`), gọi emit ngay sau `evaluate` return.

```rust
// gateway/src/proxy.rs — gần line 432
let identity = relay_detector.evaluate(peer_ip, &headers);
if let Some(emitter) = &self.audit_emitter {
    for sig in &identity.signals {
        let (rule_id, detail) = relay::audit_map::signal_to_rule_id(sig);
        emitter.emit(&audit_ctx_from(peer_ip, host_code), rule_id, "log_only", &detail);
    }
}
```

**Helper signature** trong `crates/waf-engine/src/relay/audit_map.rs`:
```rust
pub fn signal_to_rule_id(s: &Signal) -> (&'static str, String)
// Returns (rule_id, detail_json). detail_json carries variant data (hop count, asn, org).
```

Action luôn `"log_only"` (red-team F2.3). Tier-aware action mapping defer to follow-up — engine decision layer tự ghi action thật khi rule engine matches.

## Related Code Files

- Read: `crates/waf-engine/src/relay/signal.rs:30-47` (8 Signal variants)
- Read: `crates/gateway/src/proxy.rs:84-180,432` (RelayDetector field + evaluate call site)
- Create: `crates/waf-engine/src/relay/audit_map.rs` (~80 lines — 8 arms + detail builders)
- Modify: `crates/waf-engine/src/relay/mod.rs` — `pub mod audit_map;`
- Modify: `crates/gateway/src/proxy.rs` — thêm `audit_emitter: Option<Arc<AuditEmitter>>` field + setter + emit loop sau `relay_detector.evaluate` (line ~432)
- Modify: `crates/gateway/src/lib.rs` hoặc orchestration điểm `with_relay_detector` (line 171) — thêm tương đương `with_audit_emitter`
- Modify: `crates/prx-waf/src/main.rs` (hoặc bootstrap chỗ tạo gateway) — wire emitter vào proxy
- Create: `crates/gateway/tests/relay_audit_emission.rs` (~150 lines, integration test ở gateway crate vì entry point ở đây)

## Implementation Steps

1. **Read entry point** — `engine.rs`: tìm chỗ gọi `relay_registry.evaluate(...)` hoặc tương đương. Note line number into Phase 0 snapshot.
2. **Mapping module** — `relay/audit_map.rs`:
   - `pub fn signal_to_rule_id(s: &Signal) -> (&'static str, &'static str)` — exhaustive match arms.
   - `pub fn action_for_signal(s: &Signal, tier: Tier) -> &'static str` — 4 tier × 4 signal = 16 cases; mặc định `"log_only"`.
   - Unit tests trong cùng file (`#[cfg(test)] mod tests`): mỗi variant → expected rule_id + action per tier.
3. **Engine integration**:
   - Sau `evaluate()` call, iterate signals, call `emitter.emit()`.
   - Đảm bảo dedupe — nếu signals vec có duplicates (2 ProxyChain entries) → emit 2 lần là OK vì rate-limiter sẽ suppress.
4. **Integration test** (`tests/relay_audit_emission.rs`):
   - Setup test engine với postgres testcontainer + mock relay providers emit fixed signal sequences.
   - Send 1 request → assert 1 row `security_events` với rule_id `BOT-XFF-SPOOF-001`.
   - Send 2 request cùng IP trong < 60s → assert chỉ 1 row (rate-limiter active).
   - Send 1 request có 3 signals khác nhau → assert 3 row (3 rule_id khác nhau).
5. **Verify no regression**:
   - `cargo test -p waf-engine relay_` → tất cả relay existing tests pass.
6. **Docs**: update `docs/system-architecture.md` nếu cần (sequence diagram relay → emitter).

## Success Criteria

- [ ] `signal_to_rule_id` exhaustive match (compile-checked, no `_ =>` fallback đáng ngờ).
- [ ] 5 unit tests cho mapping pass.
- [ ] 3 integration tests pass.
- [ ] Existing 7 relay test files trong `crates/waf-engine/tests/relay_*.rs` không có test nào bị break.
- [ ] Coverage ≥ 90% trên `audit_map.rs`.
- [ ] Emit path không thêm latency > 5 μs per signal (verify bằng existing bench `relay_bench` + before/after).

## Risk Assessment

- **Action không xác định cho signal-only-raises-score**: nếu signal không trigger action trực tiếp, set `log_only`. Frontend filter `?action=block` sẽ miss → acceptable, frontend muốn xem tất cả thì `?action=` empty.
- **Signal enum mở rộng tương lai**: exhaustive match đảm bảo compile fail khi thêm variant — KHÔNG fallback `_ => "BOT-UNKNOWN"`.
- **Tier không lan tới gateway access phase**: tại `gateway/src/proxy.rs:432` chưa có WAF tier decision; action luôn `"log_only"` (F2.3 fix). Acceptable.

## Notes

- Phase 7 sẽ run cardinality test (1k req/s cùng IP) — không cần test ở phase này.
- Rule_id values là `&'static str` (no allocation per request).
