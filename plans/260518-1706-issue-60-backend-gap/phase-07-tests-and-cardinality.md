---
phase: 7
title: "Integration tests + cardinality validation (red-team patched)"
status: pending
priority: P0
effort: "5h"
dependencies: [2, 3, 4]
---

# Phase 7: Integration tests + cardinality validation

## Overview

Cross-phase verify: emit layer không flood DB dưới DDoS, không regress existing 7 FR plan, coverage gate giữ ≥ 90% trên module mới.

## Requirements

**Functional:**
- End-to-end test: 1k req/s sustained × 60s từ cùng 1 IP triggering relay signal → DB nhận ≤ 60 INSERT (1/60s/IP/rule_id).
- Coverage gate (CI workflow) enforce ≥ 90% line coverage trên: `audit_emitter.rs`, `relay/audit_map.rs`, `tx_velocity/audit_map.rs`, `reputation.rs`, `stats_risk_distribution.rs`.
- All existing test suites pass: `cargo test --workspace`.
- `cargo fmt --all -- --check` clean.
- `cargo clippy --workspace --all-targets -- -D warnings` clean.

**Non-functional:**
- Cardinality test runtime < 90s (CI budget).
- No memory leak: 100k unique IPs emit → memory growth < 250MB then stable across 3 GC cycles.

## Architecture

3 test layer:

### 7.1 Cardinality stress test (2 scenarios — red-team F7.1 fix)

File: `crates/waf-engine/tests/audit_emitter_cardinality.rs`.

**Scenario A — Single IP burst** (tests rate-limit suppression):
```rust
// 1 IP × 60s × 1k req/s → exactly 1 emit theo window
let emitter = AuditEmitter::new(db, BroadcastSink::noop(), AuditEmitterConfig::default());
for _ in 0..60_000 {
    emitter.emit(&fixed_ctx_single_ip, "BOT-XFF-SPOOF-MALFORMED-001", "log_only", "").await;
}
assert_eq!(emit_counter.load(Ordering::Relaxed), 1,
    "1 IP × window 60s → exactly 1 row, got {}", emit_counter);
```

**Scenario B — Botnet (10k unique IPs)** (tests channel saturation):
```rust
// 10k unique IPs × 1 emit each → DB worker must keep up
for ip in 0..10_000_u32 {
    let ctx = make_ctx_with_ip(Ipv4Addr::from(ip));
    emitter.emit(&ctx, "BOT-XFF-SPOOF-MALFORMED-001", "log_only", "").await;
}
tokio::time::sleep(Duration::from_secs(2)).await;  // drain
assert!(emit_counter.load(Ordering::Relaxed) >= 9_500,
    "expected ≥95% of 10k unique IPs persisted, got {}", emit_counter);
assert!(queue_full_dropped < 500, "drop count too high: {}", queue_full_dropped);
```

**Scenario C — Mixed burst** (single IP burst + concurrent unique IPs):
- Verify rate-limited single IP không block 10k unique fan-out.

### 7.2 Cross-FR regression sweep
Loop `cargo test -p waf-engine` + `cargo test -p waf-api`. Confirm:
- 7 relay test files xanh.
- 4 tx_velocity test files xanh.
- canary tests xanh.
- handler_stats_*, handler_reputation tests xanh.

### 7.3 Coverage gate trong CI
Sửa `.github/workflows/coverage.yml` (hoặc per-crate matrix entry):
- Thêm `--ignore-filename-regex` exclusions không gồm audit_emitter / audit_map.
- Floor ≥ 90 trên các file mới.

## Related Code Files

- Create: `crates/waf-engine/tests/audit_emitter_cardinality.rs` (~200 lines)
- Modify: `.github/workflows/coverage.yml` — bump waf-engine + waf-api coverage gate hoặc thêm scoped job cho audit_emitter
- Create: `plans/260518-1706-issue-60-backend-gap/reports/cardinality-test-result.md` (output report sau khi run)
- Read: 7 existing FR plan files (skim acceptance criteria, confirm không break)

## Implementation Steps

1. **Mock DB worker** trong test util — bound mpsc counter, không cần postgres.
2. **Cardinality test** — 1k req/s × 60s loop, assert INSERT count.
3. **Memory test** — 100k unique IPs emit, snapshot memory bằng `jemalloc-ctl` (nếu codebase dùng jemalloc) hoặc `process::stats` heuristic. Skip nếu test infra không hỗ trợ.
4. **CI coverage gate update** — verify llvm-cov scoping đúng files mới.
5. **Run full workspace test**: `cargo test --workspace`.
6. **Run docker workflow** local trên branch (`docker run rust:slim-bookworm ... cargo test`) — đảm bảo CI tương đương.
7. **Write report** `cardinality-test-result.md`: số INSERTs/min thực tế, memory peak, p99 emit latency, regression count.
8. **Notify parent plan owners** (red-team F7.5 fix — KHÔNG silent edit theo `team-coordination-rules.md`):
   - Post comment trong PR (hoặc tag issue) tham chiếu 3 plan: `260501-2003-fr007-relay-proxy-detection`, `260504-1632-fr-012-transaction-velocity`, `260506-1329-fr-025-cumulative-risk-scoring`.
   - Plan owner tự quyết định có update plan của họ không. KHÔNG edit file owner khác.

## Success Criteria

- [ ] Cardinality test pass: INSERT/min ≤ 60 cho 1 IP × 1 rule_id.
- [ ] Memory test (nếu có): residual < 250 MB sau 100k IP cycle.
- [ ] `cargo test --workspace` 100% pass.
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` 0 warnings.
- [ ] `cargo fmt --all -- --check` clean.
- [ ] CI coverage gate ≥ 90% trên 5 file mới.
- [ ] 3 parent plan files có note cross-reference plan này.

## Risk Assessment

- **Cardinality test scenario A** (red-team F7.3 fix): exact assertion `== 1` thay vì ≤ 63. 1 IP × window = đúng 1 row, không ±5%.
- **Scenario B drop tolerance** ≥ 95% — chấp nhận channel có thể drop edge cases. Nếu drop > 5% sustained → bump channel_capacity.
- **Memory test trên macOS dev** (red-team F7.2 note): không reliable do jemalloc default off. Mark `#[ignore]` trên non-Linux + thêm rule trong `CONTRIBUTING.md` (hoặc CLAUDE.md note) "must run on Linux container before push for changes touching audit_emitter".
- **End-to-end DB readback** (red-team F7.4 fix): KHÔNG đủ với mock counter. Thêm 1 test có postgres testcontainer thực, fire request → INSERT → SELECT readback assert row content.
- **CI coverage scope drift**: verify llvm-cov filter bằng `--summary-only` dry run.

## Notes

- Cardinality test là smoke test, không phải bench full DDoS. Bench thật để Attack Battle prep.
- Report `cardinality-test-result.md` lưu lại số liệu để judge có thể inspect khi cần.
