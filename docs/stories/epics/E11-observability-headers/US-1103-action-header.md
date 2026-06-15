# US-1103 X-WAF-Action enum, matches behavior in enforce

## Status

implemented

## Lane

normal

## Product Contract

Every response carries an `X-WAF-Action` header whose value is one of the defined
action enum members in lowercase exact form (interop §5.1, §5.3). When
`X-WAF-Mode: enforce`, the reported action MUST match the actual response
behavior; in `log_only` it reports the **intended** action without applying
enforcement.

## Relevant Product Docs

- `docs/product/observability-headers.md`
- interop contract v2.3 §5.1, §5.3

## Acceptance Criteria

- Every response carries exactly one `X-WAF-Action` header.
- The value is exactly one of `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker` — lowercase, exact spelling, no whitespace.
- In `enforce` mode the reported action matches the actual response behavior (e.g. `block` corresponds to a blocked response).
- In `log_only` mode the header reports the intended action while the request continues upstream.
- Any value outside the enum, or a case mismatch, is a contract failure.

## Design Notes

- Header: `X-WAF-Action`.
- Builder: gateway response-header builder in `crates/gateway/src/waf_observability_headers.rs`.
- Types: action enum / decision types in `crates/waf-common/src/types.rs`.
- Domain rules: the final decided action is serialized to its lowercase wire token; enforce mode wires the action to the actual gateway behavior.
- UI surfaces: none (machine-read by benchmarker).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Each action enum member serializes to its exact lowercase token. |
| Integration | Assert `X-WAF-Action` on each decision class equals the expected enum token and, in enforce, matches response behavior. |
| E2E | Loopback run cross-checks header action against audit-recorded action. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Header builder in gateway + crates/waf-common/src/types.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
