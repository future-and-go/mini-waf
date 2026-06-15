# E14 — Enforcement Modes (enforce / log_only)

Contract: interop v2.3 §2.5, §2.7, §5.3, §7. Product doc: `docs/product/enforcement-modes.md`.
Lane: high-risk (changes existing enforcement behavior, cross-cutting). Code:
`crates/waf-engine/src/interop/mode_registry.rs`, `crates/waf-engine/src/engine.rs`.
Tests: `crates/waf-engine/tests/engine_mode_registry.rs`,
`crates/waf-api/tests/interop_mode_enforcement.rs`.

Per-feature/policy mode resolved on the engine hot path. The §2.5 wiring gap from
`gaps.md` is the central risk this epic closes.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1401 | Resolve mode per feature/policy from registry on engine hot path | high-risk | implemented | §2.5 |
| US-1402 | log_only reports intended action, no enforcement, continues upstream | high-risk | implemented | §2.5, §5.3 |
| US-1403 | X-WAF-Mode reflects mode of policy behind final action; multi-match precedence | normal | implemented | §2.7, §5.3 |

## Acceptance criteria (per story)

- **US-1401**: the engine calls `ModeRegistry.resolve(feature, policy)` when building each
  decision (not a static `host_config.log_only_mode`); a `set_profile` toggle changes
  actual evaluation, not just the control-plane response. Regression test: toggle a
  feature to `log_only`, send triggering traffic, observe non-enforcement.
- **US-1402**: in `log_only`, a would-be `block`/`challenge`/`rate_limit`/`timeout`/
  `circuit_breaker` is reported via `X-WAF-Action` with `X-WAF-Mode: log_only`, the
  enforcement effect is NOT applied, and the request continues upstream (unless stopped
  by non-WAF transport/upstream failure). Audit evidence equals what `enforce` would write.
- **US-1403**: `X-WAF-Mode` reflects the mode of the policy that produced the final
  reported `X-WAF-Action`; when multiple policies with different modes match, the final
  action's policy mode wins.

## Validation shape

Unit: `ModeRegistry.resolve` precedence (all/feature/policy overrides). Integration:
`interop_mode_enforcement.rs` — toggle → traffic → header + non-enforcement assertions.
E2E: log_only detection visible upstream while header reports intended action.
