# US-1301 Six decision classes map to correct HTTP status/body

## Status

in_progress

## Lane

normal

## Product Contract

Every request yields exactly one of six decision classes, and each class must
produce HTTP behavior consistent with the reported `X-WAF-Action` (§3, §4). The
gateway maps `allow` to the proxied upstream response and the five denial classes
to fixed status codes (`block`→`403`, `challenge`→`429` plus challenge body,
`rate_limit`→`429`, `timeout`→`504`, `circuit_breaker`→`503`). Body format is free
(HTML/JSON/text) as long as headers stay accurate and the status matches the
action.

## Relevant Product Docs

- `docs/product/decision-classes.md`
- interop contract v2.3 §3 (decision classes), §4 (recommended HTTP)

## Acceptance Criteria

- `allow` → proxied upstream response returned (upstream status).
- `block` → `403`.
- `challenge` → `429` plus a challenge body.
- `rate_limit` → `429`.
- `timeout` → `504`.
- `circuit_breaker` → `503`.
- For every decision, HTTP behavior MUST be consistent with the reported
  `X-WAF-Action`; body format is free but status and headers stay accurate.

## Design Notes

- Commands: none.
- Queries: none.
- API: response status/body per decision; `X-WAF-Action` header reports the class.
- Tables: none.
- Domain rules: action enum in `crates/waf-common/src/types.rs`; decision→HTTP
  mapping in `crates/gateway`.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | action→status/body mapping covers all six classes. |
| Integration | per-class response shape matches reported `X-WAF-Action`. |
| E2E | request flows produce the correct status per decision. |
| Platform | n/a. |
| Release | contract behavior consistent across decision classes. |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Action enum + mapping in crates/waf-common + crates/gateway. Durable proof unset
pending `harness-cli story verify`.
