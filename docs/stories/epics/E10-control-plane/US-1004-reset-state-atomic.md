# US-1004 POST /reset_state synchronous/atomic, audit preserved

## Status

planned

## Lane

high-risk

## Product Contract

`POST /__waf_control/reset_state` clears temporary runtime state — risk state, rate-limit counters, cache, challenge/session state, temporary client/session metadata, temporary enforcement state — synchronously and atomically. Success must not return until all temporary state is cleared, and partially reset state must not be exposed after success. It must not delete, truncate, or rewrite `./waf_audit.log`; the audit log stays append-only across resets. Success body: `{ ok, action:"reset_state", audit_log_preserved:true, ts_ms }` (interop v2.3 §2.4).

## Relevant Product Docs

- `docs/product/waf-control-plane.md`
- interop v2.3 §2.4 (reset_state coverage, atomicity, audit preservation)

## Acceptance Criteria

- Clears risk state, rate-limit counters, cache, challenge/session state, temporary client/session metadata, temporary enforcement state.
- Success returns only after all temporary state is cleared (synchronous).
- Partially reset state is never observable after a success response (atomic).
- `./waf_audit.log` is not deleted, truncated, or rewritten; remains append-only.
- Success body equals `{ ok, action:"reset_state", audit_log_preserved:true, ts_ms }`.
- Secret-gated (403 without valid `X-Benchmark-Secret`).

## Design Notes

- Commands: reset temporary runtime state across the listed subsystems.
- Queries: none.
- API: `reset_state_handler` (POST) in `crates/waf-api/src/interop_control.rs`; wired in `crates/waf-api/src/server.rs`.
- Tables: none. Audit sink is file `./waf_audit.log` (append-only, preserved).
- Domain rules: synchronous + atomic clear; audit log untouched; success implies full clear.
- UI surfaces: none.
- Endpoint: POST /__waf_control/reset_state

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Reset coverage list includes every required subsystem; success body shape asserted. |
| Integration | `crates/waf-api/tests/interop_control_integration.rs` asserts post-reset state cleared, `audit_log_preserved:true`, and audit file not truncated. |
| E2E | Counters/cache observed empty in traffic following a reset; prior audit lines still present. |
| Platform | Audit file path behavior consistent on Linux/macOS. |
| Release | Append-only audit invariant holds across repeated resets. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Code present: `crates/waf-api/src/interop_control.rs`, `crates/waf-api/src/server.rs`, `crates/waf-common/src/config.rs`. Durable proof unset pending `harness-cli story verify`.
