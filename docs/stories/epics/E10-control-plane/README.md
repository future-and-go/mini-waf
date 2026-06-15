# E10 — WAF Control Plane

Contract: interop v2.3 §2. Product doc: `docs/product/waf-control-plane.md`.
Lane: high-risk (auth hard gate, public control API, audit interaction).
Code: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`,
`crates/waf-common/src/config.rs`. Tests: `crates/waf-api/tests/interop_control_integration.rs`.

Local control plane (`/__waf_control/*`) for deterministic benchmark orchestration.
All endpoints local/admin-only, secret-gated, never proxied upstream.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1001 | Mount control plane local-only, never proxied upstream | high-risk | planned | §2.1 |
| US-1002 | Benchmark-secret auth, 403 on missing/invalid | high-risk | planned | §2.2 |
| US-1003 | GET /capabilities discovery response | normal | planned | §2.3 |
| US-1004 | POST /reset_state synchronous/atomic, audit preserved | high-risk | planned | §2.4 |
| US-1005 | POST /set_profile scope/mode + unsupported partial-success | high-risk | planned | §2.5 |
| US-1006 | POST /flush_cache | normal | planned | §2.6 |

## Acceptance criteria (per story)

- **US-1001**: `/__waf_control/*` handled by the control plane, bound local/admin-only,
  and never forwarded to upstream on the proxy data path.
- **US-1002**: missing or wrong `X-Benchmark-Secret` → `403`; correct value
  (`waf-hackathon-2026-ctrl`) proceeds; constant-time compare; applies to all four endpoints.
- **US-1003**: returns `{ok, features{name:{supported,toggleable,policies[]}}, active{default_mode,overrides{}}}`;
  feature/policy names stable within a run.
- **US-1004**: clears risk, rate-limit counters, cache, challenge/session, temp client
  metadata, temp enforcement state; returns only after fully cleared; response
  `{ok, action:"reset_state", audit_log_preserved:true, ts_ms}`; MUST NOT delete/
  truncate/rewrite `./waf_audit.log`.
- **US-1005**: `scope` all/features/policies semantics honored; omitted items keep mode;
  unsupported items listed in `unsupported[]` (partial-success per decision 0008);
  response echoes `applied` + resulting `active{default_mode,overrides}`.
- **US-1006**: when caching on, clears cache before returning success; when off, clear
  not-supported response; secret-gated.

## Validation shape

Unit: secret compare, capability serialization, reset coverage list. Integration:
`interop_control_integration.rs` (all four endpoints + 403 path). E2E: control-plane
toggles observed in subsequent traffic.
