# US-1005 POST /set_profile scope/mode + unsupported partial-success

## Status

planned

## Lane

high-risk

## Product Contract

`POST /__waf_control/set_profile` toggles `enforce`/`log_only` per `scope` (`all`, `features`, or `policies`). `scope:"all"` sets the default mode for everything; `scope:"features"` changes only listed features; `scope:"policies"` changes only listed policies under `feature`, leaving siblings unchanged; omitted items keep their mode. Unsupported items are not silently ignored — supported items succeed and unsupported ones are listed in `unsupported[]` (partial-success, decision 0008). Response echoes `applied` and the resulting `active{ default_mode, overrides }` (interop v2.3 §2.5).

## Relevant Product Docs

- `docs/product/waf-control-plane.md`
- interop v2.3 §2.5 (set_profile scope/mode, partial-success per decision 0008)

## Acceptance Criteria

- `scope:"all"` sets `default_mode` for all features/policies.
- `scope:"features"` changes only listed features; omitted features keep their mode.
- `scope:"policies"` changes only listed policies under `feature`; sibling policies unchanged.
- Unsupported items returned in `unsupported[]`, never silently dropped; behavior consistent for the run.
- Response includes `applied` and resulting `active{ default_mode, overrides }`.
- Secret-gated (403 without valid `X-Benchmark-Secret`).

## Design Notes

- Commands: apply mode change scoped to all/features/policies.
- Queries: resulting `active{ default_mode, overrides }` echoed in response.
- API: `set_profile_handler` (POST) in `crates/waf-api/src/interop_control.rs`; wired in `crates/waf-api/src/server.rs`. Body: `{ scope, mode, features?[], feature?, policies?[] }`.
- Tables: none.
- Domain rules: omitted items keep mode; unsupported → `unsupported[]` (partial-success); modes `enforce`/`log_only`.
- UI surfaces: none.
- Endpoint: POST /__waf_control/set_profile

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Scope semantics (all/features/policies) and unsupported collection logic covered. |
| Integration | `crates/waf-api/tests/interop_control_integration.rs` asserts applied/active echo, partial-success `unsupported[]`, and 403 without secret. |
| E2E | Mode toggle observed in subsequent traffic via `X-WAF-Mode`. |
| Platform | Same scope behavior across platforms. |
| Release | Partial-success behavior consistent for the whole run. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Code present: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`. Durable proof unset pending `harness-cli story verify`.
