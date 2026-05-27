---
phase: 1
title: "Transport Dispatch Completion"
status: completed
priority: P1
effort: "4h"
dependencies: []
---

# Phase 1: Transport Dispatch Completion

## Overview

The QUIC transport server and client currently handle only 6 of 13 message types (Heartbeat, JoinRequest/Response, ElectionVote, ElectionResult). The remaining 7 types (RuleSyncRequest, RuleSyncResponse, ConfigSync, EventBatch, StatsBatch, ApiForward, ApiForwardResponse, NodeLeave) hit a catch-all `other =>` branch and are silently ignored.

This phase adds dispatch arms for every message type so subsequent phases can rely on messages being routed correctly.

## Requirements

- Functional: All 13 `ClusterMessage` variants must be dispatched to handler functions
- Non-functional: No new allocations in the hot path; handler functions can be stubs that log + return Ok

## Architecture

```
ClusterMessage received via QUIC stream
  → frame::read_frame() deserializes JSON
  → dispatch_message() matches variant
  → routes to handler function (may be stub in this phase)
```

## Related Code Files

- Modify: `crates/waf-cluster/src/transport/server.rs` (dispatch_message, ~line 174)
- Modify: `crates/waf-cluster/src/transport/client.rs` (dispatch_incoming, ~line 190)
- Modify: `crates/waf-cluster/src/protocol.rs` (verify all variants exist)

## TDD: Tests First

1. Write test in `crates/waf-cluster/tests/transport_dispatch_coverage.rs`:
   - For each `ClusterMessage` variant, serialize → deserialize round-trip
   - Verify `dispatch_message` returns `Ok(())` for every variant (not `unhandled`)
   - Test that `NodeLeave` removes peer from `NodeState.peers`

2. Tests should FAIL initially (catch-all ignores messages)

## Implementation Steps

1. **Server dispatch** (`transport/server.rs`):
   - Add match arms for `RuleSyncRequest` → call `handle_rule_sync_request()` (stub: log + respond with empty RuleSyncResponse)
   - Add `ConfigSync` → call `handle_config_sync()` (stub: log)
   - Add `EventBatch` → call `handle_event_batch()` (stub: log + ack)
   - Add `StatsBatch` → call `handle_stats_batch()` (stub: log)
   - Add `ApiForward` → call `handle_api_forward()` (stub: log + respond with 501)
   - Add `NodeLeave` → call `handle_node_leave()` (remove peer from state)
   - Remove the catch-all `other =>` — make match exhaustive

2. **Client dispatch** (`transport/client.rs`):
   - Add match arms for `RuleSyncResponse` → call `handle_rule_sync_response()` (stub: log)
   - Add `ConfigSync` → call `handle_config_sync()` (stub: log)
   - Add `ApiForwardResponse` → call `handle_api_forward_response()` (stub: log)
   - Add `EventBatch` / `StatsBatch` → log (workers shouldn't receive these normally)
   - Remove catch-all, make match exhaustive

3. **Run tests** — all dispatch coverage tests should pass

## Success Criteria

- [ ] All 13 `ClusterMessage` variants have explicit match arms in server dispatch
- [ ] All 13 `ClusterMessage` variants have explicit match arms in client dispatch
- [ ] No catch-all `other =>` / `_ =>` in dispatch functions
- [ ] `cargo test -p waf-cluster` passes with new dispatch coverage tests
- [ ] `cargo check --workspace` passes with zero warnings

## Risk Assessment

- Low risk: purely additive match arms, stub handlers preserve current behavior
- Pitfall: forgetting to update dispatch when new message types are added later → mitigated by exhaustive match (compiler catches it)
