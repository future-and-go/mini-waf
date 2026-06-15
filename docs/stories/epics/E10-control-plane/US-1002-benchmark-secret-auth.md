# US-1002 Benchmark-secret auth, 403 on missing/invalid

## Status

planned

## Lane

high-risk

## Product Contract

Every control request must carry `X-Benchmark-Secret: waf-hackathon-2026-ctrl`. Missing or invalid secret returns `403 Forbidden`; the correct value proceeds. The compare is constant-time, and the guard applies to all four control endpoints (interop v2.3 §2.2). This is an auth hard gate.

## Relevant Product Docs

- `docs/product/waf-control-plane.md`
- interop v2.3 §2.2 (authentication, `X-Benchmark-Secret`, 403 on missing/invalid)

## Acceptance Criteria

- Request missing `X-Benchmark-Secret` header → `403 Forbidden`.
- Request with wrong secret value → `403 Forbidden`.
- Request with correct value (`waf-hackathon-2026-ctrl`) → proceeds to handler.
- Secret comparison uses constant-time equality (no early-exit on mismatch).
- Guard applies uniformly to `capabilities`, `reset_state`, `set_profile`, `flush_cache`.
- 403 path returns no control-plane side effects (no state change).

## Design Notes

- Commands: none.
- Queries: none.
- API: `benchmark_secret_guard` middleware in `crates/waf-api/src/interop_control.rs` wraps the control route group; secret sourced from config in `crates/waf-common/src/config.rs`.
- Tables: none.
- Domain rules: constant-time compare via `constant_time_eq`; auth hard gate on all four endpoints.
- UI surfaces: none.
- Endpoint: (guard) all /__waf_control/* methods

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | `constant_time_eq` returns correct boolean; equal-length and unequal-length inputs covered. |
| Integration | `crates/waf-api/tests/interop_control_integration.rs` covers 403 on missing/invalid secret and pass on valid secret for each endpoint. |
| E2E | Control toggle rejected without secret; accepted with correct secret. |
| Platform | Header handling consistent across listeners. |
| Release | Default secret value matches contract; no secret leaked in logs. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Code present: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`. Durable proof unset pending `harness-cli story verify`.
