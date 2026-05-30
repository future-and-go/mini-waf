---
phase: 6
title: "Inject on Pre-Inspect + Error Paths"
status: pending
priority: P1
effort: "3h"
dependencies: [2, 3]
---

# Phase 6: Inject on Pre-Inspect + Error Paths

## Overview
Cover every egress path that runs BEFORE `engine.inspect()` (so no `WafDecision`/snapshot exists)
or via Pingora error handling: access-gate block (403), fail-closed 503, HTTP→HTTPS redirect (301),
health 200, and transport errors (`fail_to_proxy`). Contract requires the 6 headers on EVERY
response, including these (red-team F2, F5, F7). Raised to P1.

## Requirements
- Functional: each path carries all 6 headers with the correct action; works when `request_ctx` is `None`.
- Non-functional: build values inline (no snapshot at these points); `cache = Bypass`.

## Architecture
These paths build their own `ResponseHeader` (often via `ErrorPageFactory::render` →
`(ResponseHeader, Bytes)`; error_page_factory.rs:22). Inject into the returned header at each call
site (the factory has no ctx/req_id, so do NOT inject inside it):

| Path | Location | action | req_id source |
|---|---|---|---|
| Access-gate block | proxy.rs:662-672 | `block` | `request_ctx.req_id` (built before gate) |
| Fail-closed 503 | `request_filter` fail-closed arm | `circuit_breaker` (or `block`) | `request_ctx` if Some, else fallback (OQ2) |
| HTTP→HTTPS redirect 301 | `request_filter` early arm | `allow` | `request_ctx.req_id` if available |
| Health 200 | `request_filter` health arm | `allow` | fallback (see note) |
| Transport error | `fail_to_proxy` (proxy.rs:1039) | `timeout` (504) / `circuit_breaker` (503) / `block` | `ctx.request_ctx` if Some, else fallback |

For all: `risk` from `ctx.waf_decision_meta` if present else 0, `rule_id=none`, `mode`=global default, `cache=Bypass`.

**req_id fallback + audit correlation (validate decision: write minimal audit stub):** when
`request_ctx` is `None`, generate a fresh `Uuid::new_v4()` AND write a minimal audit-log entry keyed
by that id (status/action/ts at least) so `X-WAF-Request-Id` is always correlatable (§5↔§6). Locate
the audit writer used elsewhere and emit a reduced record on these ctx-less error paths. When
`request_ctx` IS present, reuse its `req_id` (already audited).

**Health note:** if `/health` is served via Pingora `respond_error` (no mutable header access), the 6
headers may be impractical to inject. If so, document it as an explicit exception in Phase 7 (the
benchmarker uses `/health` only for startup liveness, not classification). Prefer injecting if the
header object is reachable.

## Related Code Files
- Modify: `crates/gateway/src/proxy.rs` (access-gate, fail-closed, redirect, health arms in `request_filter`; `fail_to_proxy`)
- Read for context: `crates/gateway/src/error_page/error_page_factory.rs:22`

## Implementation Steps
1. Access-gate block arm: build `WafHeaderValues` inline (`action="block"`, req from `request_ctx`); inject into rendered headers.
2. Fail-closed 503 arm: inline values; when `request_ctx` None → fresh UUID + write minimal audit stub; inject.
3. Redirect 301 + health arms: inject (or document health exception).
4. `fail_to_proxy`: map `error_to_status` → action (504 timeout / 503 circuit_breaker / else block); req_id from ctx or fallback; inject.
5. Tests for 403 (access-gate), 503, 504, 301 responses carrying all 6 headers; ctx-None case carries `X-WAF-Request-Id`.

## Success Criteria
- [ ] access-gate 403, fail-closed 503, redirect 301, transport 504/503 carry all 6 headers
- [ ] correct `X-WAF-Action` per path (block/circuit_breaker/allow/timeout)
- [ ] `X-WAF-Request-Id` present even when `request_ctx` was None, AND a matching minimal audit entry is written (correlatable)
- [ ] health path: injected OR documented exception
- [ ] `cargo test -p gateway` green; clippy clean

## Risk Assessment
- Risk: error path may not expose a mutable header before send (health/`respond_error`) → document exception, keep changes surgical.
- Risk: Timeout/CircuitBreaker have no live producer yet (§3 RT-10) → test via injected errors at unit/factory level.

## Security Considerations
- Error responses add only the 6 contract headers; no upstream internals leaked.
- Fallback `request_id` must be a valid UUID v4 format even when uncorrelatable.
