# US-1102 X-WAF-Risk-Score 0–100 after evaluation

## Status

implemented

## Lane

normal

## Product Contract

Every response carries an `X-WAF-Risk-Score` header expressing the accumulated
risk for the {IP+device+session} identity **after** evaluating the current
request (interop §5.1, §5.3). The value is a plain integer in `0..=100` with no
whitespace or formatting. The header is present on allowed responses too, since
the benchmarker uses it for risk accumulation and decay checks.

## Relevant Product Docs

- `docs/product/observability-headers.md`
- interop contract v2.3 §5.1, §5.3

## Acceptance Criteria

- Every response carries exactly one `X-WAF-Risk-Score` header.
- The value is a plain base-10 integer in the inclusive range 0 to 100, with no leading/trailing whitespace, sign, decimal point, or thousands separators.
- The score reflects the {IP+device+session} risk state computed after the current request is evaluated (post-update, not the pre-request value).
- The header is present on `allow` responses, not only on enforced decisions.
- Out-of-range or non-integer values are a contract failure.

## Design Notes

- Header: `X-WAF-Risk-Score`.
- Builder: gateway response-header builder in `crates/gateway/src/waf_observability_headers.rs`.
- Types: risk-score / decision types in `crates/waf-common/src/types.rs`.
- Domain rules: the post-evaluation accumulated score is read from the engine's risk state for the request identity and rendered as a bare integer clamped to 0..=100.
- UI surfaces: none (machine-read by benchmarker).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Builder renders the score as a bare integer in 0..=100 for representative inputs. |
| Integration | Assert `X-WAF-Risk-Score` present on each decision class, including allow, with a valid 0–100 integer. |
| E2E | Loopback run cross-checks header risk score against audit-recorded score. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Header builder in gateway + crates/waf-common/src/types.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
