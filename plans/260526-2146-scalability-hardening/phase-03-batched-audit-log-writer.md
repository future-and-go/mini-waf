---
phase: 3
title: "Batched Audit Log Writer (DB)"
finding: F5
status: pending
priority: P1
effort: "3h"
dependencies: []
---

# Phase 3: Batched Audit Log Writer (DB)

## Overview

`log_attack()` (engine.rs:830) and `log_security_event()` (engine.rs:872) each fire `tokio::spawn` per detection to INSERT into PostgreSQL. Under sustained attack (5k+ blocks/sec), unbounded spawns exhaust DB pool and risk OOM. Replace with bounded MPSC channel + single background batch writer.

**NOTE**: Existing `logging/batch_buffer.rs` batches writes to **VictoriaLogs** (HTTP). This phase creates a new writer for **PostgreSQL** DB INSERTs, following the same proven pattern but targeting sqlx.

## Key Insights

- Two spawn sites: `log_attack` (engine.rs:830) → `db.create_attack_log()`, `log_security_event` (engine.rs:872) → `db.create_security_event()`
- 15 call sites invoke these two functions (engine.rs:518-757)
- Existing `BatchSender` (logging/batch_buffer.rs) provides proven pattern: bounded mpsc, `try_send`, rate-limited warn on full, timer-based flush
- `create_attack_log` and `create_security_event` target different tables with different schemas
- Research: 10k channel cap, flush every 100ms or 1000 events, `try_send` never blocks

## Requirements

**Functional:**
- Replace per-detection `tokio::spawn` with `try_send` into bounded channel
- Single background worker handles both event types
- Batch INSERT via sqlx `QueryBuilder` (multi-row INSERT)
- On channel full: drop event with rate-limited `warn!` (fail-open)
- Graceful shutdown: flush remaining on channel close

**Non-functional:**
- Hot path: zero async, single `try_send` (~50ns)
- Throughput: 5k events/sec sustained
- Memory: bounded ~10k events x ~1KB = ~10MB max

## Architecture

**Data flow:**
```
log_attack() / log_security_event()
  → try_send(DbLogEvent) into bounded mpsc (10k cap)
    → Full? drop + rate-limited warn
    → Ok: enqueued

Background worker:
  loop {
    select! {
      event = rx.recv() → batch.push; if len >= 1000 { flush() }
      _ = ticker.tick() → if !empty { flush() }
    }
  }

flush():
  → batch INSERT via sqlx QueryBuilder
  → on error: warn + drop batch (fail-open)
```

## Related Code Files

| File | Action | LOC Est. | Test Impact |
|------|--------|----------|-------------|
| `crates/waf-engine/src/logging/db_batch_writer.rs` | Create | ~120 | 4 new tests |
| `crates/waf-engine/src/logging/mod.rs` | Modify | +3 lines | — |
| `crates/waf-engine/src/engine.rs` | Modify | ~20 changed | 2 functions changed |
| `crates/waf-storage/src/repo.rs` | Modify | ~40 (batch insert) | 2 new tests |

## Tests Before (TDD)

1. **Test: try_send on full channel drops event**
   - Create `DbBatchWriter` with capacity=2
   - Send 3 events, assert 3rd dropped

2. **Test: batch flush on size threshold**
   - Writer with batch_size=3, send 3 events
   - Assert: flush triggered

3. **Test: batch flush on timer**
   - Writer with batch_size=1000, flush_interval=50ms
   - Send 1 event, wait 100ms
   - Assert: event flushed despite not reaching batch_size

4. **Test: channel close flushes remaining**
   - Drop all senders, assert pending events flushed

## Implementation Steps

1. **Create `crates/waf-engine/src/logging/db_batch_writer.rs`**:

   ```rust
   use std::sync::Arc;
   use std::time::Duration;
   use tokio::sync::mpsc;
   use waf_storage::Database;
   use waf_storage::models::{AttackLog, CreateSecurityEvent};

   pub enum DbLogEvent {
       Attack(AttackLog),
       Security(CreateSecurityEvent),
   }

   #[derive(Clone)]
   pub struct DbBatchWriter {
       tx: mpsc::Sender<DbLogEvent>,
   }

   impl DbBatchWriter {
       pub fn spawn(
           db: Arc<Database>,
           capacity: usize,      // default 10_000
           batch_size: usize,    // default 1_000
           flush_interval_ms: u64, // default 100
       ) -> Self {
           let (tx, rx) = mpsc::channel(capacity);
           tokio::spawn(flush_loop(rx, db, batch_size, flush_interval_ms));
           Self { tx }
       }

       pub fn try_send(&self, event: DbLogEvent) {
           match self.tx.try_send(event) {
               Ok(()) => {}
               Err(mpsc::error::TrySendError::Full(_)) => {
                   // Rate-limited warn (reuse pattern from batch_buffer.rs)
                   // RED-TEAM: document that event loss is acceptable for observability logs
                   // Add metric counter for dropped events for compliance monitoring
               }
               Err(mpsc::error::TrySendError::Closed(_)) => {
                   // RED-TEAM FIX: batch writer is dead — log at error level
                   error!("Audit batch writer channel closed; events lost");
               }
           }
       }
   }
   ```

2. **Implement `flush_loop`** — same `tokio::select!` pattern as `batch_buffer.rs:131-171`:
   - Collect into `Vec<AttackLog>` and `Vec<CreateSecurityEvent>`
   - On threshold/timer: call batch insert, clear, warn on error

3. **Add batch INSERT methods** to `crates/waf-storage/src/repo.rs`:
   - `create_attack_log_batch(pool, logs: &[AttackLog])` using `sqlx::QueryBuilder` multi-row VALUES
   - `create_security_event_batch(pool, events: &[CreateSecurityEvent])` — same pattern
   - Chunk to 1000 rows per statement (PostgreSQL bind limit ~65535 params)
   - **RED-TEAM FIX**: Use `ON CONFLICT DO NOTHING` on batch INSERT to prevent one bad row killing entire batch

4. **Register module** in `logging/mod.rs`:
   ```rust
   pub mod db_batch_writer;
   pub use db_batch_writer::DbBatchWriter;
   ```

5. **Replace spawns in `engine.rs`**:

   ```rust
   // engine.rs: add field to WafEngine (or use OnceLock<DbBatchWriter>)
   
   // BEFORE (engine.rs:829-834):
   let db = Arc::clone(&self.db);
   tokio::spawn(async move {
       if let Err(e) = db.create_attack_log(log).await { warn!(...); }
   });
   
   // AFTER:
   if let Some(writer) = self.db_batch_writer.get() {
       writer.try_send(DbLogEvent::Attack(log));
   }
   ```

   Same for `log_security_event` at engine.rs:871-876.

6. **Initialize writer** in engine construction (main.rs init path), store in `WafEngine` via `OnceLock`

## Refactor

Key changes:
- `engine.rs:829-834`: remove `tokio::spawn`, replace with `writer.try_send(Attack(log))`
- `engine.rs:871-876`: remove `tokio::spawn`, replace with `writer.try_send(Security(event))`
- `engine.rs:60`: add `db_batch_writer: OnceLock<DbBatchWriter>` field to `WafEngine` struct + update `WafEngine::new()`

## Tests After (TDD)

1. **Test: batch INSERT produces multi-row SQL**
   - Mock DB, send 5 attack logs, assert single INSERT

2. **Test: 5k events/sec sustained 10s without OOM**
   - Benchmark with mock DB

3. **Test: existing single-row create_attack_log still works**
   - Backward compatibility for other callers

## Regression Gate

```bash
cargo check -p waf-engine -p waf-storage
cargo test -p waf-engine -- log_attack
cargo test -p waf-engine -- batch
cargo test -p waf-storage
```

## Success Criteria

- [ ] Zero `tokio::spawn` in `log_attack()` and `log_security_event()`
- [ ] Bounded channel (10k default) with `try_send`
- [ ] Batch INSERT (up to 1000 rows per statement)
- [ ] Timer-based flush (100ms)
- [ ] Rate-limited warn on channel full
- [ ] 4+ new tests passing
- [ ] `cargo check --workspace` clean

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Batch INSERT slower (index contention) | Low | Medium | Start batch_size=100, benchmark, tune up |
| Event loss on channel full during DDoS | Medium | Medium | Acceptable for observability; **RED-TEAM**: add dropped_events counter metric for compliance monitoring (PCI-DSS/SOC2 audit trail) |
| Writer crash orphans pending events | Low | Low | Graceful drain on channel close; events idempotent |

## Test Scenario Matrix

| Scenario | Priority | Type |
|----------|----------|------|
| try_send on empty channel → success | Critical | Unit |
| try_send on full channel → drop + warn | Critical | Unit |
| Batch flush on size threshold | Critical | Unit |
| Batch flush on timer interval | Critical | Unit |
| Graceful shutdown flushes remaining | High | Unit |
| Multi-row INSERT SQL correctness | High | Integration |
| 5k events/sec sustained load | Medium | Benchmark |

## Dependency Map

- **Depends on**: nothing
- **Blocks**: Phase 7 (integration)
- **Cross-plan**: cluster plan Phase 4 can reuse batch channel for event forwarding
- **File ownership**: `engine.rs`, `logging/db_batch_writer.rs`, `repo.rs` — exclusive to this phase
