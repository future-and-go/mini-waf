# US-1101 X-WAF-Request-Id (UUID v4) + audit correlation

## Status

implemented

## Lane

normal

## Product Contract

Every response returned through the WAF carries an `X-WAF-Request-Id` header that
is a canonical UUID v4 and equals the `request_id` recorded in the audit log for
the same request (interop §4, §5.1). The header is the correlation anchor between
client-visible responses and audit lines; a missing, malformed, or mismatched id
is an observability contract failure even when the HTTP status and body look
correct.

## Relevant Product Docs

- `docs/product/observability-headers.md`
- interop contract v2.3 §4 (minimum), §5.1, §5.3

## Acceptance Criteria

- Every response (all decision classes) carries exactly one `X-WAF-Request-Id` header.
- The value is a UUID v4 (RFC 4122, version nibble `4`, variant `8/9/a/b`), lowercase canonical form, no surrounding whitespace.
- The header value byte-for-byte equals the audit-log `request_id` for the same request.
- A missing, malformed, or audit-mismatched id is treated as a contract failure.
- The same id is reused for all headers and audit lines emitted for one request (no regeneration mid-pipeline).

## Design Notes

- Header: `X-WAF-Request-Id`.
- Builder: gateway response-header builder in `crates/gateway/src/waf_observability_headers.rs`.
- Types: request-id / decision types in `crates/waf-common/src/types.rs`.
- Domain rules: id generated once per request, threaded through evaluation and audit emission so the response header and audit `request_id` share one source.
- UI surfaces: none (machine-read by benchmarker).

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Header builder emits a valid UUID v4 string for the request id. |
| Integration | Assert `X-WAF-Request-Id` present on each decision class and equal to the audit `request_id`. |
| E2E | Loopback run cross-checks response `X-WAF-Request-Id` against audit lines. |
| Platform | n/a |
| Release | n/a |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof booleans set via harness-cli after verification.

## Evidence

Header builder in gateway + crates/waf-common/src/types.rs. Durable proof recorded 2026-06-15: status=implemented, unit=1 integration=1 e2e=0 (e2e/benchmark loopback deferred); see harness.db.
