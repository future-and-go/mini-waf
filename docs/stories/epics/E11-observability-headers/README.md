# E11 — Observability Headers

Contract: interop v2.3 §4 (min), §5. Product doc: `docs/product/observability-headers.md`.
Lane: normal (public contract). Code: response-header builder in `crates/gateway` +
`crates/waf-common/src/types.rs`. The six `X-WAF-*` headers MUST be on every response.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1101 | X-WAF-Request-Id (UUID v4) + audit correlation | normal | implemented | §4, §5.1 |
| US-1102 | X-WAF-Risk-Score 0–100 after evaluation | normal | implemented | §5.1, §5.3 |
| US-1103 | X-WAF-Action enum, matches behavior in enforce | normal | implemented | §5.1, §5.3 |
| US-1104 | X-WAF-Rule-Id attribution or `none` | normal | implemented | §5.1, §5.3 |
| US-1105 | X-WAF-Mode enforce/log_only correlation | normal | implemented | §5.1, §5.3 |
| US-1106 | All required headers present on every decision class incl. allow | normal | implemented | §5, §5.3 |

## Acceptance criteria (per story)

- **US-1101**: every response carries `X-WAF-Request-Id` as a UUID v4 that equals the
  audit-log `request_id`; missing/malformed/mismatched → observability contract failure.
- **US-1102**: `X-WAF-Risk-Score` is a plain integer 0–100 with no whitespace, reflecting
  the score for {IP+device+session} **after** evaluating the current request; present on
  allowed responses (used for accumulation/decay checks).
- **US-1103**: `X-WAF-Action` ∈ {allow,block,challenge,rate_limit,timeout,circuit_breaker},
  lowercase exact; matches actual behavior when `X-WAF-Mode: enforce`.
- **US-1104**: `X-WAF-Rule-Id` identifies the rule/model/policy/detector behind the action;
  `none` when no specific detector applies; alphanumeric + hyphens.
- **US-1105**: `X-WAF-Mode` is `enforce` or `log_only`, reflecting the mode of the policy
  that produced the final reported action (see E14).
- **US-1106**: all six required headers present on allow/block/challenge/rate_limit/timeout/
  circuit_breaker responses; `X-WAF-Cache` defaults to `BYPASS` (see E15).

## Validation shape

Unit: header-builder per decision class. Integration: assert all six headers on each
class. E2E: loopback run cross-checks headers ↔ audit lines.
