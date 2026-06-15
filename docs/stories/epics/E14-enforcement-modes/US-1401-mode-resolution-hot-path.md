# US-1401 Resolve mode per feature/policy from registry on engine hot path

## Status

implemented

## Lane

high-risk

## Product Contract

Each feature/policy runs in `enforce` or `log_only`, resolved per feature/policy when the engine builds each decision (§2.5). The engine MUST resolve the active mode from the mode registry on the hot path, not from a static per-host flag, so a `set_profile` toggle takes effect immediately on real evaluation rather than only changing the control-plane response. The registry is the single source of truth for active mode and its `scope:"all" | "features" | "policies"` overrides.

## Relevant Product Docs

- `docs/product/enforcement-modes.md`
- interop v2.3 §2.5 (mode resolution / update scopes), §2.7, §5.3

## Acceptance Criteria

- When building each decision, the engine calls `ModeRegistry.resolve(feature, policy)` rather than reading a static `host_config.log_only_mode` flag.
- `ModeRegistry.resolve` honors precedence: `policy` override > `feature` override > `scope:"all"` default.
- A `set_profile` toggle that writes the registry changes actual traffic evaluation, not only the control-plane response.
- Regression: toggle a feature to `log_only`, send triggering traffic, and observe non-enforcement (the would-be effect is not applied) while the intended action is still reported.
- Toggling the same feature back to `enforce` restores enforcement on the next request without restart.

## Design Notes

- Commands: `set_profile` writes mode + override scopes into the registry.
- Queries: `ModeRegistry.resolve(feature, policy)` called per decision on the hot path.
- API: decision build in `crates/waf-engine/src/engine.rs` consumes the resolved mode.
- Tables: registry state held by `crates/waf-engine/src/interop/mode_registry.rs`.
- Domain rules: resolution precedence policy > feature > all; registry read per request.
- Risk: per `gaps.md`, the engine historically read `host_config.log_only_mode` instead of the registry, so a `set_profile` toggle changed only the control-plane response and never reached evaluation. This story closes that wiring gap.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | `ModeRegistry.resolve` precedence (all/feature/policy overrides) in `crates/waf-engine/tests/engine_mode_registry.rs`. |
| Integration | `crates/waf-api/tests/interop_mode_enforcement.rs` — toggle feature to `log_only`, send triggering traffic, assert non-enforcement; toggle back, assert enforcement. |
| E2E | log_only detection visible upstream while header reports intended action. |
| Platform | n/a. |
| Release | n/a. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

ModeRegistry in crates/waf-engine/src/interop/mode_registry.rs; engine wiring in engine.rs; tests interop_mode_enforcement.rs / engine_mode_registry.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
