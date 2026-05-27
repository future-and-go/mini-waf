---
phase: 4
title: "Event Log Aggregation"
status: completed
priority: P2
effort: "4h"
dependencies: [1]
---

# Phase 4: Event Log Aggregation

## Overview

Workers detect attacks independently but currently don't forward security events to the main node for centralized logging. The `EventBatcher` exists and works, but nothing feeds events into it, and the main node has no handler to persist received events.

This phase connects the WAF detection pipeline to the cluster event forwarding system.

### Validation Decisions

- **Event durability**: Drop during downtime (at-most-once). No buffering or replay during main downtime. Simplest approach for v1 — workers still keep local logs.

### Red-Team Fixes

- **Batch DB inserts**: Use `INSERT ... VALUES (...), (...), ...` instead of N individual inserts to avoid N+1 bottleneck under sustained attack.
- **Source tagging**: Add `source_node_id` field to stored events to distinguish local vs forwarded events, preventing double-counting on main.

## Requirements

- Functional: Security events detected on workers are batched and forwarded to main
- Functional: Main node persists received events to PostgreSQL via batch insert
- Functional: Events tagged with `source_node_id` to distinguish origin
- Non-functional: Batching with configurable size (100) and flush interval (5s)
- Non-functional: At-most-once delivery — events during main downtime are dropped (v1 decision)
- Non-functional: No buffering/replay during election window

## Architecture

```
Worker:
  WafEngine detects attack → SecurityEvent
    → event_tx.send(event)          // existing broadcast channel
    → EventBatcher collects events
    → on batch full OR timer tick:
       → ClusterMessage::EventBatch { events }
       → send to main via QUIC

Main:
  receives EventBatch
    → handle_event_batch()
    → for each event: db.insert_security_event(event)
    → broadcast to WebSocket subscribers
```

## Related Code Files

- Modify: `crates/waf-cluster/src/sync/events.rs` — wire `EventBatcher` to actual event source
- Modify: `crates/waf-cluster/src/transport/server.rs` — real `handle_event_batch()` (replace stub)
- Modify: `crates/waf-cluster/src/node.rs` — add event channel receiver
- Modify: `crates/waf-cluster/src/lib.rs` — spawn `run_event_batcher()` in `ClusterNode::run()`
- Read: `crates/waf-engine/src/engine.rs` — how SecurityEvents are emitted
- Read: `crates/waf-storage/src/db.rs` — `insert_security_event()` method
- Read: `crates/waf-api/src/state.rs` — `event_tx` broadcast channel

## TDD: Tests First

1. **Unit test** (`crates/waf-cluster/tests/event_forwarding_test.rs`):
   - Create `EventBatcher` with batch_size=3, flush_interval=100ms
   - Push 5 events
   - Assert: first batch of 3 sent immediately, remaining 2 sent after timer
   - Verify batches arrive on the output channel

2. **Main handler test**:
   - Simulate receiving `EventBatch` on main node
   - Assert `handle_event_batch()` calls storage insert (mock or in-memory)

3. **Backpressure test**:
   - Fill queue to `events_queue_size` (10000)
   - Push one more event
   - Assert oldest event dropped (bounded channel behavior)

## Implementation Steps

1. **Add event input channel to NodeState** (`node.rs`):
   - Add `event_rx: parking_lot::Mutex<Option<mpsc::Receiver<SecurityEvent>>>` 
   - Add `event_tx: mpsc::Sender<SecurityEvent>` for feeding events
   - Create bounded channel in `NodeState::new()`

2. **Wire WafEngine events to cluster** (`lib.rs` or `main.rs`):
   - Subscribe to `AppState.event_tx` broadcast
   - Forward received events to `node_state.event_tx`

3. **Spawn EventBatcher** (`lib.rs`):
   - In `ClusterNode::run()`, if role == Worker:
     - Take `event_rx` from NodeState
     - Spawn `run_event_batcher(event_rx, batch_size, flush_interval, peer_tx)`

4. **Real `handle_event_batch`** (`transport/server.rs`):
   - Deserialize `EventBatch`
   - If main has storage (StorageMode::Full):
     - Insert each event via `db.insert_security_event()`
   - Re-broadcast to WebSocket subscribers via `event_tx`

5. **Run tests** — all event forwarding tests pass

## Success Criteria

- [ ] Workers batch and forward security events to main
- [ ] Main persists forwarded events to PostgreSQL
- [ ] Main broadcasts forwarded events to WebSocket subscribers
- [ ] Batching respects size and time thresholds
- [ ] Bounded channel prevents memory exhaustion under backpressure
- [ ] `cargo test -p waf-cluster` passes
- [ ] `cargo check --workspace` passes

## Risk Assessment

- Medium risk: requires connecting WafEngine event pipeline to cluster
- Pitfall: double-counting events on main (local + forwarded) → tag events with `source_node_id`
- Pitfall: event serialization size — SecurityEvent may be large → lz4 compress batches >1KB
