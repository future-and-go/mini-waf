---
phase: 1
title: "Shared audit emitter + rate limiter (red-team patched)"
status: pending
priority: P0
effort: "6h"
dependencies: [0]
---

# Phase 1: Shared audit emitter + rate limiter

## Overview

Module mới `crates/waf-engine/src/audit_emitter.rs` — building block cho phase 2/3/4. Red-team patched: bucket-claim ordering, try_send semantics, WS broadcast decouple, feature flag, worker supervisor, TTL = window (1 knob).

## Requirements

**Functional:**
- `AuditEmitter::new(db, broadcast_sink, config) -> Self` — đầu vào: `Arc<Database>`, `Arc<dyn BroadcastSink>` (trait abstract WS broadcast), `AuditEmitterConfig`.
- `fn emit(&self, ctx, rule_id, action, detail) -> EmitOutcome` — returns enum `Emitted | RateLimited | QueueFullDropped | Disabled`.
- `AuditEmitterConfig { enabled: bool, window_secs: u64, max_keys: usize, channel_capacity: usize }` — defaults (post-validation):
  - `enabled`: NO hardcoded default. Đọc từ TOML config với env-layered override (V1): `[audit_emitter] enabled` ở base, overridden bởi `[audit_emitter.staging] enabled=true` / `[audit_emitter.prod] enabled=false`. Layer pattern phải verify trong Phase 0 (config.rs hiện đã support env layering chưa?).
  - `window_secs`: 60
  - `max_keys`: 100_000
  - `channel_capacity`: **auto-tune** = `num_cpus::get().saturating_mul(256).max(512)` (V3). On 8-core CI: 2048; on 32-core prod: 8192. Override-able qua TOML cho test/bench. **Phase 0 verify** `num_cpus` crate availability (likely qua tokio's dep tree).
- `enabled = false` short-circuits emit (no bucket, no broadcast, no DB).
- **TTL = window** (1 knob): bucket entry expires đúng `window_secs` sau emit thành công. Red-team F1.7 fix.

**Non-functional:**
- Hot-path emit: < 1 μs khi disabled, < 5 μs khi enabled+rate-limited, < 10 μs khi enabled+queued.
- Memory ≤ 150 MB tại worst-case (50k IP × 30 rule_id × 100 bytes).
- Metrics (4 counters): `audit.emitted`, `audit.rate_limited`, `audit.queue_full_dropped`, `audit.worker_restarted`. Metric crate chốt ở Phase 0.

## Architecture (red-team patched ordering)

```
emit(ctx, rule_id, action, detail) -> EmitOutcome
├── if !cfg.enabled → return Disabled (no allocation)
├── 1. WS broadcast FIRST (cheap, never rate-limited per CC4 fix):
│     broadcast_sink.send(LiveEvent { ip, rule_id, action, detail })  // try_send, drop if WS subscriber buffer full
├── 2. check_bucket(key):
│     match buckets.get(&key) → entry exists + not expired → metric `rate_limited` → return RateLimited
│     (bucket NOT yet inserted)
├── 3. build CreateSecurityEvent
├── 4. tx.try_send(event):
│     Ok          → CLAIM bucket NOW (buckets.insert(key, expires_ms = now + window_secs))
│                   metric `emitted`, return Emitted
│     Err(Full)   → drop event (NEW event dropped — clarified per F1.2), metric `queue_full_dropped`
│                   bucket NOT claimed → caller có thể retry next request (no 120s blackout)
│                   return QueueFullDropped
│     Err(Closed) → channel closed (worker dead) → return QueueFullDropped (caller không tell apart)
└── done

worker (supervised tokio::spawn):
    loop {
        let handle = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(e) = db.create_security_event(event).await {
                    warn!(?e, "audit insert failed");  // F1.4 mode (4): metric `audit.db_insert_failed`
                }
            }
        });
        if let Err(panic) = handle.await {
            warn!(?panic, "audit worker panicked, restarting");
            metric.worker_restarted.inc();
            tokio::time::sleep(Duration::from_secs(1)).await;
            continue;
        }
        break;  // graceful shutdown
    }

janitor (tokio::spawn):
    interval window_secs:
        purge expired entries
        if live > max_keys: LRU evict oldest by expires_ms
```

**Key ordering changes from red-team:**
- F1.3 — **bucket claim AFTER successful `try_send`**, not before. Test: queue Full → bucket NOT poisoned, next request emits successfully.
- F1.2 — clarify `try_send` drops NEW event (not oldest); metric name `queue_full_dropped` reflects.
- F1.5/CC4 — WS broadcast OUTSIDE rate-limit gate. WS subscribers see every detection; DB persists 1/window/IP/rule_id.
- F1.4 — worker supervisor task wraps `tokio::spawn`; auto-restart on panic + 1s backoff.
- F1.7 — TTL = window (single knob).

## BroadcastSink trait

```rust
pub trait BroadcastSink: Send + Sync {
    fn try_broadcast(&self, evt: LiveEvent) -> Result<(), BroadcastError>;
}

// Production impl wraps existing `broadcast_event` from waf-storage::repo or whatever WS hub
// Test impl: counter that increments without WS
```

**Why trait**: decouples emitter từ storage layer; phase 1 test với mock sink, phase 7 wire vào WS hub thật.

**Production impl** (V4 locked): `BroadcastSink::production()` wrap pattern từ `crates/waf-storage/src/repo.rs:430 broadcast_event(event_json)`. Phase 0 walk verify chuỗi `broadcast_event` → WS hub → subscriber để confirm consumer thật sự nhận events (verify CC4 từ red-team).

## Related Code Files

- Create: `crates/waf-engine/src/audit_emitter.rs` (~300 lines — increased từ 250 do supervisor + broadcast)
- Create: `crates/waf-engine/src/audit_emitter/broadcast.rs` (~50 lines — BroadcastSink trait + production impl)
- Modify: `crates/waf-engine/src/lib.rs` — `pub mod audit_emitter;`
- Modify: `crates/waf-common/src/config.rs` — `[audit_emitter]` section trong TOML config
- Modify: `crates/waf-engine/src/engine.rs` — inject `AuditEmitter` field; **KHÔNG** thay đổi `log_security_event` hiện tại (per F1 red-team: replacing engine.rs:858 không reduce DDoS load vì decision-level rate-limit đã có 1/rule_match/request). Engine giữ nguyên đường log_security_event; emitter chỉ được phase 2/3/4 call ở detection layer.
- Reference: `crates/waf-engine/src/checks/ddos/store/memory.rs` (DashMap + GC pattern)
- Create: `crates/waf-engine/tests/audit_emitter_unit.rs` (~200 lines, ≥ 10 tests)

## Implementation Steps

1. **Config**: add `AuditEmitterConfig` struct + `[audit_emitter]` section trong global TOML. Default `enabled = true`. Hot-reload optional (YAGNI cho phase này; kill-switch bằng config reload đủ).
2. **BroadcastSink trait** + production impl `WsBroadcastSink` wrap existing WS hub (find ở `waf-api/src/websocket.rs` qua Phase 0 walk).
3. **Module skeleton**: `struct AuditEmitter { buckets, tx, sink, _gc_handle, _worker_handle, cfg, metrics }`.
4. **`new()` constructor**:
   - Khởi tạo `DashMap` với `with_capacity(max_keys / 4)`.
   - `let (tx, rx) = mpsc::channel(channel_capacity);`
   - Spawn worker supervisor (loop with restart-on-panic).
   - Spawn janitor.
5. **`emit()` method** theo Architecture sequence — bucket claim AFTER try_send Ok.
6. **`gc()` private**: purge expired + LRU eviction nếu vượt `max_keys`.
7. **Disabled fast path**: if `!cfg.enabled` return `Disabled` ngay đầu — zero alloc.
8. **Tests** (`audit_emitter_unit.rs`):
   - `disabled_config_short_circuits` (no DB, no WS)
   - `emit_first_time_succeeds_and_broadcasts`
   - `emit_within_window_rate_limited_but_broadcasts` (F1.5 fix verify: WS receives, DB skipped)
   - `emit_after_window_succeeds`
   - `gc_removes_expired_entries`
   - `gc_evicts_oldest_when_over_cap`
   - `concurrent_emit_same_key_one_wins_bucket`
   - **`queue_full_does_not_poison_bucket`** (F1.3 verify: full channel → no bucket claimed → next request emits)
   - **`worker_panic_restarts`** (F1.4 verify: kill worker task, next emit eventually persists)
   - `ws_broadcast_independent_of_rate_limit` (F1.5 verify)
9. **Engine integration** — inject emitter qua constructor. **Không** thay log_security_event hiện tại.

## Success Criteria

- [ ] Module compiles, clippy clean với `-D warnings`.
- [ ] 10 unit tests pass (đặc biệt F1.3/F1.4/F1.5 regression tests).
- [ ] Disabled fast-path bench < 100 ns (zero-overhead toggle).
- [ ] Coverage ≥ 90% line on `audit_emitter.rs` + `broadcast.rs`.
- [ ] Bench: 5k emit/s sustained, p99 emit < 10 μs khi enabled.
- [ ] Feature flag toggle qua config reload (no recompile).

## Risk Assessment (post red-team)

- **Bucket claim ordering** đã sửa, có test guard.
- **Worker panic** đã có supervisor, có test guard.
- **WS broadcast loss** đã decouple, có test guard.
- **Disabled mode**: nếu accidentally `enabled=false` ship to prod → 0 audit events → silent. Mitigation: startup log `audit_emitter: enabled=true (or false)` ở INFO level, dashboard widget hiển thị flag.
- **Channel cap 512 trong burst sustained**: nếu DB latency 50ms × 512 = 25.6s đệm; sustained 5k unique req/s overruns trong < 0.1s (red-team F7.1). **Mitigation**: bench thực tế trong Phase 7 với DB-in-loop, có thể bump cap → 4096 nếu test fail.
- **30 rule_id cardinality claim không enforced** (CC3): mitigation = `rule_id: &'static str` constants ở Phase 2/3/4 mappings, lookup table check.

## Notes

- `std::sync::Mutex` BANNED per CLAUDE.md. DashMap không vi phạm.
- File hint 300 dòng — nếu chạm 350 dòng, tách `gc.rs`, `worker.rs`, `metrics.rs` riêng.
