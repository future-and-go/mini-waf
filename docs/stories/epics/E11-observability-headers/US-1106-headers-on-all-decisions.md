# US-1106 All required headers present on every decision class incl. allow

## Status

implemented

## Lane

normal

## Product Contract

All six required `X-WAF-*` headers are present on every response returned through
the WAF, across every decision class — `allow`, `block`, `challenge`,
`rate_limit`, `timeout`, and `circuit_breaker` (interop §5, §5.3). Missing any
required header is a contract failure even when the HTTP status and body look
correct. `X-WAF-Cache` defaults to `BYPASS` when caching is not engaged.

## Relevant Product Docs

- `docs/product/observability-headers.md`
- interop contract v2.3 §5, §5.1, §5.3

## Acceptance Criteria

- Every response carries all six required headers: `X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`.
- The full set is present on each decision class: `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker`.
- The `allow` class is not exempt — required headers appear on allowed responses (used for risk accumulation/decay checks).
- `X-WAF-Cache` defaults to the uppercase sentinel `BYPASS` for non-cacheable routes or when caching is disabled (see E15).
- Any missing required header on any decision class is a contract failure regardless of status/body correctness.

## Design Notes

- Headers: `X-WAF-Request-Id`, `X-WAF-Risk-Score`, `X-WAF-Action`, `X-WAF-Rule-Id`, `X-WAF-Cache`, `X-WAF-Mode`.
- Builder: gateway response-header builder in `crates/gateway/src/waf_observability_headers.rs` applied on every response path.
- Types: decision / action / mode types in `crates/waf-common/src/types.rs`.
- Domain rules: the builder emits the complete required-header set unconditionally for all decision classes; `X-WAF-Cache` falls back to `BYPASS`.
- UI surfaces: none (machine-read by benchmarker).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Builder emits all six required headers for each decision class, with `X-WAF-Cache` defaulting to `BYPASS`. |
| Integration | Assert all six headers present on `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker` responses. |
| E2E | Loopback run cross-checks the full header set against audit lines for each decision class. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Header builder in gateway + crates/waf-common/src/types.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
