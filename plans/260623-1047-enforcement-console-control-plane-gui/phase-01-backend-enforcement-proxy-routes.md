---
phase: 1
title: "Backend Enforcement Proxy Routes"
status: pending
priority: P1
dependencies: []
effort: "M"
---

# Phase 1: Backend Enforcement Proxy Routes

## Overview

Add four JWT-guarded `/api/enforcement/*` routes that mirror the secret-gated
`/__waf_control/*` control plane, so the operator browser never holds
`X-Benchmark-Secret`. Responses are byte-identical to the control-plane contract.
This unblocks all FE data fetching (Phases 3–5).

## Requirements

- Functional: expose, under the existing `require_auth` JWT middleware:
  - `GET  /api/enforcement/capabilities` → mirror of `GET  /__waf_control/capabilities`
  - `POST /api/enforcement/set-profile` → mirror of `POST /__waf_control/set_profile`
  - `POST /api/enforcement/reset-state` → mirror of `POST /__waf_control/reset_state`
  - `POST /api/enforcement/flush-cache` → mirror of `POST /__waf_control/flush_cache`
- Non-functional: zero logic duplication between the secret-gated and JWT routes
  (single source of truth → identical shapes forever). No `X-Benchmark-Secret`
  acceptance on these routes. Same `mode_registry` instance services both.

## Architecture

```
Browser ──Bearer JWT──▶ /api/enforcement/*  ─┐
                                             ├─▶ enforcement_core::{capabilities,set_profile,reset_state,flush_cache}(&AppState, body) ─▶ ModeRegistry
benchmarker ──secret──▶ /__waf_control/*  ───┘
```

**Refactor for DRY (required):** the current handlers in
`crates/waf-api/src/interop_control.rs` embed their logic inline behind
`benchmark_secret_guard`. Extract each handler body into a `pub(crate)` function
that takes `&AppState` (and the parsed request body where applicable) and returns
a `serde_json::Value`. Both route groups call these. Keep the JSON shapes exactly
as they are today (verified):

- capabilities → `{ ok, features{<name>:{supported,toggleable,policies}}, active{default_mode,overrides} }`
- set_profile → `{ ok, action:"set_profile", applied{...}, active{...}, unsupported[], ts_ms }`
- reset_state → `{ ok, action:"reset_state", audit_log_preserved:true, ts_ms }`
- flush_cache → `{ ok, action:"flush_cache", ts_ms }`

The set_profile request body type is unchanged:
`{ scope:"all"|"features"|"policies", mode:"enforce"|"log_only", features?, feature?, policies? }`.

**Auth pattern (verified):** register the four routes inside the
`protected_routes` router in `crates/waf-api/src/server.rs` (around lines
121–304, before the `.layer(require_auth)` is applied to that router). Reuse
`crate::middleware::require_auth` exactly as the ~40 existing `/api/*` routes do.
No new middleware. Handlers take `State(state): State<Arc<AppState>>` and access
`state.mode_registry` (`crates/waf-api/src/state.rs:70`).

**interop-disabled behavior:** the spec FE treats a 404 as "control plane
disabled (`interop.enabled = false`)". Decide and document the response when
`state.interop_config` indicates interop disabled: return `404` with
`{ ok:false, error:"interop disabled" }` from the `/api/enforcement/*` handlers
so the FE Result-state branch (Phase 7) is real. If interop has no enabled flag
that gates these routes today, document that the routes are always available and
the FE disabled-state branch is defensive only. Confirm against
`state.interop_config` fields before finalizing.

## Related Code Files

- Modify: `crates/waf-api/src/interop_control.rs` — extract handler bodies into
  reusable `pub(crate)` core fns; keep existing secret-gated routes calling them.
- Modify: `crates/waf-api/src/server.rs` — register the four `/api/enforcement/*`
  routes in `protected_routes`; import the new handler fns.
- Reference (no change): `crates/waf-api/src/state.rs` (mode_registry),
  `crates/waf-api/src/middleware.rs` (require_auth),
  `crates/waf-engine/src/interop/feature_catalog.rs` (catalog),
  `crates/waf-engine/src/interop/mode_registry.rs` (precedence).
- Tests: extend `crates/waf-api/tests/interop_control_integration.rs` or add a
  sibling test module for the JWT routes.

## Implementation Steps

1. In `interop_control.rs`, extract four `pub(crate)` core functions:
   `capabilities_value(&AppState) -> Value`,
   `set_profile_value(&AppState, SetProfileBody) -> Value`,
   `reset_state_value(&AppState) -> Value`,
   `flush_cache_value(&AppState) -> Value`. Move existing handler bodies into them.
2. Rewrite the existing secret-gated handlers to delegate to the core fns (verify
   shapes unchanged by re-running the existing interop tests).
3. Add JWT handlers (in `interop_control.rs` or a small `enforcement.rs`) named
   e.g. `enforcement_capabilities`, `enforcement_set_profile`,
   `enforcement_reset_state`, `enforcement_flush_cache`, each
   `State<Arc<AppState>>` (+ `Json<SetProfileBody>` for set-profile) delegating
   to the core fns.
4. Register the four routes in `server.rs` `protected_routes`.
5. Resolve the interop-disabled question (see Architecture); implement the chosen
   response and note it in plan Open Questions resolution.
6. Run `cargo fmt`, `cargo clippy -p waf-api`, and the targeted tests.

## Success Criteria

- [ ] `GET /api/enforcement/capabilities` with a valid Bearer returns the same
      JSON as `GET /__waf_control/capabilities` with the secret (assert in test).
- [ ] `POST /api/enforcement/set-profile` applies to `mode_registry` and the next
      `capabilities` call reflects it; response includes `applied`, `active`,
      `unsupported`, `ts_ms`.
- [ ] reset-state returns `audit_log_preserved:true`; flush-cache returns `ok`.
- [ ] All four `/api/enforcement/*` routes reject requests without a valid JWT
      (401) and do NOT accept `X-Benchmark-Secret`.
- [ ] Existing `/__waf_control/*` tests still pass (shapes unchanged).
- [ ] `cargo test -p waf-api` green; clippy clean.

## Risk Assessment

- **Shape drift between the two route groups.** Mitigated by the shared core fns
  and an integration test asserting JWT and secret responses are equal.
- **Accidentally exposing mutating routes without auth.** Mitigated by placing
  them inside `protected_routes` and a negative test (no-JWT → 401).
- **interop-disabled ambiguity.** Resolved explicitly in step 5; do not guess at
  implementation time.

Rollback: routes are additive; remove the four `.route(...)` lines and the JWT
handlers. The core-fn extraction is behavior-preserving and can stay.
