# E13 — Decision Classes & Actions

Contract: interop v2.3 §3, §4, §7. Product doc: `docs/product/decision-classes.md`.
Lane: normal (public contract). Code: action enum in `crates/waf-common/src/types.rs`,
decision mapping in `crates/gateway`.

Every request yields exactly one of six decisions, each with consistent HTTP behavior.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1301 | Six decision classes map to correct HTTP status/body | normal | in_progress | §3, §4 |
| US-1302 | Threat category → action acceptable-set mapping | normal | in_progress | §3.1 |

## Acceptance criteria (per story)

- **US-1301**: `allow`→upstream response; `block`→`403`; `challenge`→`429`+challenge body;
  `rate_limit`→`429`; `timeout`→`504`; `circuit_breaker`→`503`. Body format is free but
  HTTP behavior MUST be consistent with the reported `X-WAF-Action`.
- **US-1302**: chosen action falls within the acceptable set for each threat category in
  §3.1 (e.g. high-confidence injection → `block`/`challenge`, never `allow`/`rate_limit`/
  `timeout`; volumetric single-source → `rate_limit`/`block`, never `circuit_breaker`;
  upstream degradation → `circuit_breaker`). Actions target the actor responsible.

## Validation shape

Unit: action→status/body mapping. Integration: per-class response shape. E2E: threat
fixtures asserted within acceptable action set.
