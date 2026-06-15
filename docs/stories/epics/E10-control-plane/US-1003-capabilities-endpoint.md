# US-1003 GET /capabilities discovery response

## Status

planned

## Lane

normal

## Product Contract

`GET /__waf_control/capabilities` returns a discovery body `{ ok, features{ name: { supported, toggleable, policies[] } }, active{ default_mode, overrides{} } }`. Feature and policy names are implementation-defined but must stay stable within a run so the benchmarker can rely on them across calls (interop v2.3 §2.3).

## Relevant Product Docs

- `docs/product/waf-control-plane.md`
- interop v2.3 §2.3 (capabilities discovery shape)

## Acceptance Criteria

- Response is JSON with top-level `ok`, `features`, `active`.
- Each feature entry exposes `supported`, `toggleable`, `policies[]`.
- `active` contains `default_mode` and `overrides{}`.
- Feature/policy names are stable across repeated calls within one run.
- Secret-gated (returns 403 without valid `X-Benchmark-Secret`).

## Design Notes

- Commands: none.
- Queries: capability snapshot read from runtime feature/policy registry.
- API: `capabilities_handler` (GET) in `crates/waf-api/src/interop_control.rs`; mounted in route group from `crates/waf-api/src/server.rs`.
- Tables: none.
- Domain rules: names stable within a run; serialization matches `{ ok, features{...}, active{...} }`.
- UI surfaces: none.
- Endpoint: GET /__waf_control/capabilities

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Capability serialization produces the required field shape; names deterministic. |
| Integration | `crates/waf-api/tests/interop_control_integration.rs` asserts capabilities body shape and 403 without secret. |
| E2E | Benchmarker discovers features then toggles them by the returned names. |
| Platform | Identical body across supported platforms. |
| Release | Feature/policy name set documented and stable for the run. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Code present: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`. Durable proof unset pending `harness-cli story verify`.
