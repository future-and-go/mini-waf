# Product: Enforcement Modes (enforce / log_only)

Source: interop contract v2.3 §2.5, §2.7, §5.3, §7 (log-only rule).
Implementation: `crates/waf-engine/src/interop/mode_registry.rs`,
`crates/waf-engine/src/engine.rs`. Epic: `E14`.

Each feature/policy runs in one of two modes, resolved **per feature/policy**:

- `enforce`: the decision's `X-WAF-Action` is applied to traffic (e.g. a `block`
  actually blocks before upstream).
- `log_only`: the policy is evaluated normally and MUST still report the intended
  `X-WAF-Action`, `X-WAF-Rule-Id`, and audit evidence that `enforce` would produce,
  but the enforcement effect MUST NOT be applied. A would-be `block`/`challenge`/
  `rate_limit`/`timeout`/`circuit_breaker` reports the intended action with
  `X-WAF-Mode: log_only` while the request continues upstream (unless stopped by
  non-WAF transport/upstream failure).

## Mode resolution (hot path)

The engine MUST resolve the active mode from the mode registry when building each
decision — not from a static per-host flag. `set_profile` writes the registry
(`docs/product/waf-control-plane.md`); the engine reads it per request so a toggle
takes effect immediately. `X-WAF-Mode` reflects the mode of the policy that
produced the **final reported** `X-WAF-Action` (§2.7, §5.3). When multiple policies
with different modes match, the mode of the policy behind the final action wins.

> Known risk (`gaps.md`): historically the engine derived mode from
> `host_config.log_only_mode` and ignored the registry. US-1401 verifies the
> registry is wired into the hot path and that a `set_profile` toggle actually
> changes evaluation, not just the control-plane response.

## Update scopes (§2.5)

- `scope:"all"` → default mode for all features/policies; clears prior overrides
  unless reported in `active.overrides`.
- `scope:"features"` → only listed features change; omitted keep their mode.
- `scope:"policies"` → only listed policies under `feature` change; siblings keep
  their mode.

## Normalization in log_only (§7)

`log_only` + detection → benchmarker classification `log_only_detected`. Because
the request continues upstream, the unsafe effect may still occur even though the
WAF correctly reported an intended `block`/`challenge`/`rate_limit`. This is
expected and is how the benchmarker verifies a detector without forcing every test
request to be denied.
