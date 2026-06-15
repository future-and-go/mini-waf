# US-1104 X-WAF-Rule-Id attribution or `none`

## Status

implemented

## Lane

normal

## Product Contract

Every response carries an `X-WAF-Rule-Id` header identifying the rule, model,
policy, or detector that most directly caused the decision (interop §5.1, §5.3).
When no specific detector applies, the header is the literal sentinel `none`.
The id is composed of alphanumeric characters and hyphens.

## Relevant Product Docs

- `docs/product/observability-headers.md`
- interop contract v2.3 §5.1, §5.3

## Acceptance Criteria

- Every response carries exactly one `X-WAF-Rule-Id` header.
- A non-`none` value matches `[A-Za-z0-9-]+` (alphanumeric plus hyphens), no whitespace.
- When no specific rule/model/policy/detector caused the decision, the value is exactly the lowercase sentinel `none`.
- The id corresponds to the detector that most directly drove the reported action (single, most-responsible attribution).
- An empty value or characters outside the allowed set is a contract failure.

## Design Notes

- Header: `X-WAF-Rule-Id`.
- Builder: gateway response-header builder in `crates/gateway/src/waf_observability_headers.rs`.
- Types: rule-id / decision attribution types in `crates/waf-common/src/types.rs`.
- Domain rules: the decision records the most-responsible detector id; absence renders the `none` sentinel rather than an empty header.
- UI surfaces: none (machine-read by benchmarker).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Builder renders a valid rule id and the `none` sentinel for the no-detector case. |
| Integration | Assert `X-WAF-Rule-Id` present on each decision class with a valid id or `none`. |
| E2E | Loopback run cross-checks header rule id against audit-recorded attribution. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Header builder in gateway + crates/waf-common/src/types.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
