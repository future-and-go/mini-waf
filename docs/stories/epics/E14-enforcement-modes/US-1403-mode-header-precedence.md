# US-1403 X-WAF-Mode reflects mode of policy behind final action; multi-match precedence

## Status

implemented

## Lane

normal

## Product Contract

`X-WAF-Mode` reflects the mode of the policy that produced the final reported `X-WAF-Action` (§2.7, §5.3). When multiple policies with different modes match the same request, the mode of the policy behind the final action wins; `X-WAF-Mode` is not the mode of an earlier or losing match.

## Relevant Product Docs

- `docs/product/enforcement-modes.md`
- interop v2.3 §2.7 (final action selection), §5.3 (header reporting)

## Acceptance Criteria

- `X-WAF-Mode` equals the mode of the policy that produced the final reported `X-WAF-Action`.
- When multiple policies with different modes match, the final action's policy mode is reported, not an earlier match's mode.
- A single-policy match reports that policy's mode unchanged.
- Header reporting is consistent regardless of policy evaluation order for the same final action.

## Design Notes

- Commands: none new.
- Queries: resolved mode of the winning policy is attached to the final decision.
- API: final-action selection and header emission in `crates/waf-engine/src/engine.rs`.
- Tables: registry state in `crates/waf-engine/src/interop/mode_registry.rs`.
- Domain rules: `X-WAF-Mode` tracks the policy behind the final `X-WAF-Action`; multi-match precedence resolves to the winning policy's mode.
- Risk: per `gaps.md`, the engine historically read `host_config.log_only_mode` instead of the registry, which would emit a host-wide mode rather than the winning policy's resolved mode.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | winning-policy mode attached to final decision in `crates/waf-engine/tests/engine_mode_registry.rs`. |
| Integration | `crates/waf-api/tests/interop_mode_enforcement.rs` — multi-match traffic asserts `X-WAF-Mode` reflects the final action's policy mode. |
| E2E | header reports the mode of the policy behind the final action upstream. |
| Platform | n/a. |
| Release | n/a. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

ModeRegistry in crates/waf-engine/src/interop/mode_registry.rs; engine wiring in engine.rs; tests interop_mode_enforcement.rs / engine_mode_registry.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
