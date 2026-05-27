---
phase: 6
title: "Write Forwarding Integration"
status: completed
priority: P2
effort: "4h"
dependencies: [1, 5]
---

# Phase 6: Write Forwarding Integration

## Overview

`PendingForwards` and `forward_write()` exist in `cluster_forward.rs` but the API layer never calls them. Workers currently reject or silently fail write requests. This phase wires the API layer to detect when the node is a worker and forward POST/PUT/DELETE/PATCH requests to the main node via QUIC.

### Red-Team Critical Fixes (from review)

- **BLOCKER #3**: JWT secret not synced between nodes → forwarded requests fail auth on main. Fix: sync JWT secret via cluster config sync (Phase 5 dependency), OR include JWT secret in cluster crypto config so all nodes share it.
- **Auth bypass via localhost replay**: `replay_request()` sends to `127.0.0.1`, bypassing IP-based controls. Fix: tag forwarded requests with original client IP and enforce it in the main's handler.
- **Frame size limit**: `read_frame` has no max-size guard. Fix: enforce 1MB max payload for ApiForward.

## Requirements

- Functional: Write requests on worker API are transparently forwarded to main
- Functional: Worker returns the main's response to the original client (HTTP 200/201/etc)
- Functional: If main unreachable, worker returns HTTP 503 "cluster main unavailable"
- Functional: Both worker AND main validate JWT independently (user decision)
- Functional: JWT signing secret shared via cluster config (added to `[cluster.crypto]`)
- Non-functional: Forward timeout configurable (default 10s)
- Non-functional: Max ApiForward payload size: 1MB

## Architecture

```
Client → Worker API (POST /api/rules)
  → is_write_method(POST) == true
  → node is Worker role
  → serialize request → ApiForward { method, path, body, headers }
  → send via QUIC to main
  → main receives ApiForward
  → main replays request against local API router
  → main sends ApiForwardResponse { status, body, headers }
  → worker deserializes response
  → worker returns to client
```

## Related Code Files

- Modify: `crates/waf-api/src/server.rs` — add middleware/layer for write forwarding
- Modify: `crates/waf-cluster/src/transport/server.rs` — real `handle_api_forward()` (replace stub)
- Modify: `crates/waf-cluster/src/transport/client.rs` — real `handle_api_forward_response()`
- Modify: `crates/waf-cluster/src/cluster_forward.rs` — add `replay_request()` on main
- Read: `crates/waf-cluster/src/cluster_forward.rs` — existing `PendingForwards`, `forward_write()`
- Read: `crates/waf-api/src/state.rs` — AppState structure

## TDD: Tests First

1. **Unit test** (`crates/waf-cluster/tests/write_forwarding_test.rs`):
   - Create mock main and worker NodeState
   - Worker calls `forward_write()` with a POST request
   - Assert `ApiForward` message sent to main channel
   - Main replies with `ApiForwardResponse { status: 201, body: "{...}" }`
   - Assert worker receives the response within timeout

2. **Timeout test**:
   - Worker calls `forward_write()` with 100ms timeout
   - Main never responds
   - Assert worker gets timeout error

3. **Main handler test**:
   - Main receives `ApiForward { method: POST, path: "/api/rules", body: ... }`
   - Assert `replay_request()` executes the request locally
   - Assert response sent back as `ApiForwardResponse`

## Implementation Steps

1. **API middleware** (`waf-api/src/server.rs`):
   - Add an Axum middleware layer that checks:
     - Is this a write method? (`is_write_method()`)
     - Is cluster enabled and node role == Worker?
   - If both true: intercept request, call `forward_write()`, return forwarded response
   - If not: pass through to normal handler

2. **Wire `handle_api_forward` on main** (`transport/server.rs`):
   - Deserialize `ApiForward`
   - Call `replay_request()` which constructs an HTTP request and sends to `127.0.0.1:API_PORT`
   - Capture response → build `ApiForwardResponse`
   - Send back on the QUIC stream

3. **Wire `handle_api_forward_response` on worker** (`transport/client.rs`):
   - Look up pending forward by correlation ID in `PendingForwards`
   - Complete the oneshot channel with the response

4. **503 fallback**:
   - If `forward_write()` fails (timeout, channel closed), return:
     - HTTP 503 with body `{"error": "cluster main unavailable"}`

5. **Run tests** — all write forwarding tests pass

## Success Criteria

- [ ] Worker API forwards write requests to main transparently
- [ ] Main replays forwarded requests and returns real responses
- [ ] Worker returns 503 when main is unreachable
- [ ] Read-only requests on workers are served locally (not forwarded)
- [ ] Forward timeout is configurable
- [ ] `cargo test -p waf-cluster` passes
- [ ] `cargo check --workspace` passes

## Risk Assessment

- Medium risk: HTTP request replay on main needs careful header/body handling
- Pitfall: forwarded request headers may include worker's Host → strip/replace
- Pitfall: large request bodies (file uploads) → set max body size for forwards (1MB)
- Pitfall: correlation ID collision → use UUID v4 (already in workspace deps)
