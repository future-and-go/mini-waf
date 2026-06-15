# Product: Observability Headers

Source: interop contract v2.3 §4 (minimum), §5. Epic: `E11`.

The benchmarker classifies decisions primarily from required `X-WAF-*` response
headers. Missing required headers are a contract failure, even when HTTP
status/body looks correct. Headers MUST appear on **every** response returned
through the WAF, including `allow`, `block`, `challenge`, `rate_limit`, `timeout`,
and `circuit_breaker`.

## Required headers (§5.1)

| Header | Type | Rule |
| --- | --- | --- |
| `X-WAF-Request-Id` | UUID v4 | Canonical id; MUST equal audit-log `request_id`. |
| `X-WAF-Risk-Score` | int 0–100 | Accumulated risk for {IP+device+session} **after** evaluating this request. Plain integer, no whitespace. |
| `X-WAF-Action` | enum | One of `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`; lowercase, exact. In `log_only` this is the **intended** action. |
| `X-WAF-Rule-Id` | string or `none` | Rule/model/policy/detector that most directly caused the decision; `none` when no specific detector applies. Alphanumeric + hyphens. |
| `X-WAF-Cache` | `HIT`/`MISS`/`BYPASS` | Uppercase exact. `BYPASS` for non-cacheable routes or when caching is disabled. See `docs/product/caching-observability.md`. |
| `X-WAF-Mode` | `enforce`/`log_only` | Mode of the policy that produced the final reported action. See `docs/product/enforcement-modes.md`. |

## Consistency rules (§5.3)

- `X-WAF-Action` MUST match actual response behavior when `X-WAF-Mode: enforce`.
- In `log_only`, report the intended `X-WAF-Action` but do not apply enforcement;
  the request SHOULD continue upstream.
- `X-WAF-Risk-Score` reflects the score after the current request.
- `X-WAF-Rule-Id` is `none` when no specific rule/model/policy caused the decision.
- `X-WAF-Cache` is `BYPASS` on authenticated/dynamic/sensitive/high-risk routes.
- `X-WAF-Request-Id` MUST match the audit-log `request_id` for the same request.
- Required headers MUST be present on allowed responses too (used for risk
  accumulation/decay checks).

## Additional headers (§5.2)

Extra `X-WAF-*` headers are allowed for dashboards/forensics. They MUST use the
`X-WAF-` prefix, MUST NOT weaken any required header, and MUST NOT contain secrets,
credentials, session tokens, stack traces, or sensitive data.
