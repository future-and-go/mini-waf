# US-1402 log_only reports intended action, no enforcement, continues upstream

## Status

implemented

## Lane

high-risk

## Product Contract

In `log_only`, the policy is evaluated normally and MUST still report the intended `X-WAF-Action`, `X-WAF-Rule-Id`, and audit evidence that `enforce` would produce, but the enforcement effect MUST NOT be applied (§2.5, §5.3). A would-be `block`/`challenge`/`rate_limit`/`timeout`/`circuit_breaker` reports the intended action with `X-WAF-Mode: log_only` while the request continues upstream, unless stopped by a non-WAF transport/upstream failure.

## Relevant Product Docs

- `docs/product/enforcement-modes.md`
- interop v2.3 §2.5 (log-only rule), §5.3 (header reporting)

## Acceptance Criteria

- In `log_only`, a would-be `block`/`challenge`/`rate_limit`/`timeout`/`circuit_breaker` is reported via `X-WAF-Action` with `X-WAF-Mode: log_only`.
- The enforcement effect is NOT applied for any of those actions in `log_only`.
- The request continues upstream (unless stopped by a non-WAF transport/upstream failure).
- Audit evidence written in `log_only` equals what `enforce` would write for the same detection (including `X-WAF-Rule-Id`).
- `X-WAF-Mode: enforce` paths remain unchanged: the reported action is actually applied.

## Design Notes

- Commands: none new; mode comes from the resolved registry value.
- Queries: resolved mode gates whether the decision's effect is applied.
- API: decision-application branch in `crates/waf-engine/src/engine.rs` honors `log_only` by reporting but not applying.
- Tables: registry state in `crates/waf-engine/src/interop/mode_registry.rs`.
- Domain rules: report-intended-action-without-effect for all five enforcement action types; audit parity with `enforce`.
- Risk: per `gaps.md`, the engine historically read `host_config.log_only_mode` instead of the registry, which could mis-gate the apply branch. Non-enforcement must key off the registry-resolved mode.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | mode-gated apply branch in `crates/waf-engine/tests/engine_mode_registry.rs`. |
| Integration | `crates/waf-api/tests/interop_mode_enforcement.rs` — assert `X-WAF-Action` + `X-WAF-Mode: log_only`, non-enforcement, upstream continuation, and audit parity with `enforce`. |
| E2E | log_only detection visible upstream while header reports intended action. |
| Platform | n/a. |
| Release | n/a. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

ModeRegistry in crates/waf-engine/src/interop/mode_registry.rs; engine wiring in engine.rs; tests interop_mode_enforcement.rs / engine_mode_registry.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
