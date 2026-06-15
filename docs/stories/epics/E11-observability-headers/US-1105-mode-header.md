# US-1105 X-WAF-Mode enforce/log_only correlation

## Status

implemented

## Lane

normal

## Product Contract

Every response carries an `X-WAF-Mode` header that is either `enforce` or
`log_only`, reflecting the mode of the policy that produced the final reported
action (interop §5.1, §5.3). The mode value correlates with `X-WAF-Action`
semantics: `enforce` means the action was applied, `log_only` means the action
was intended but not applied and the request continued upstream.

## Relevant Product Docs

- `docs/product/observability-headers.md`
- interop contract v2.3 §5.1, §5.3

## Acceptance Criteria

- Every response carries exactly one `X-WAF-Mode` header.
- The value is exactly `enforce` or `log_only` — lowercase, exact, no whitespace.
- The mode reflects the policy that produced the final reported action, not a global default.
- When the value is `enforce`, the reported `X-WAF-Action` matches actual response behavior; when `log_only`, the action is intended only and the request continues upstream.
- Any value other than `enforce` or `log_only` is a contract failure.

## Design Notes

- Header: `X-WAF-Mode`.
- Builder: gateway response-header builder in `crates/gateway/src/waf_observability_headers.rs`.
- Types: mode / policy decision types in `crates/waf-common/src/types.rs`.
- Domain rules: the effective mode of the policy that produced the final action is serialized; correlates with enforcement-mode behavior (see E14).
- UI surfaces: none (machine-read by benchmarker).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Builder serializes the policy mode to exactly `enforce` or `log_only`. |
| Integration | Assert `X-WAF-Mode` present on each decision class with a valid mode correlated to enforcement behavior. |
| E2E | Loopback run cross-checks header mode against audit-recorded mode. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Header builder in gateway + crates/waf-common/src/types.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
