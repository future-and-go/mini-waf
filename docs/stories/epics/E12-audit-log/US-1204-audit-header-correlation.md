# US-1204 request_id / mode correlation with response headers

## Status

implemented

## Lane

normal

## Product Contract

For the same request, the audit record's `request_id` MUST match the
`X-WAF-Request-Id` response header and its `mode` MUST match the `X-WAF-Mode`
response header (interop v2.3 §6). This lets the benchmarker correlate each audit
line to the response it produced. The audit log supplements, and does not replace,
the §5 response headers.

## Relevant Product Docs

- `docs/product/audit-log.md`
- interop contract v2.3 §6 (header correlation), §10 (source-IP trust model)

## Acceptance Criteria

- Each audit record's `request_id` equals the `X-WAF-Request-Id` header for the
  same request.
- Each audit record's `mode` equals the `X-WAF-Mode` header for the same request.
- Correlation holds line-to-header across a run for every processed request.

## Design Notes

- Commands: emit `request_id` and `mode` into both the response headers and the
  audit record from one decision context.
- Queries: read-back is a direct parse of `./waf_audit.log` to correlate to headers;
  the VictoriaLogs read proxy is removed (US-1205).
- API: record emission in
  `crates/waf-engine/src/logging/audit_sender.rs`.
- Tables: none — JSONL, one JSON object per line.
- Domain rules: `request_id` ↔ `X-WAF-Request-Id`; `mode` ↔ `X-WAF-Mode`,
  consistent per request.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Record carries the same `request_id`/`mode` values supplied to the headers. |
| Integration | Line-to-header correlation: audit `request_id`/`mode` match `X-WAF-*` headers. |
| E2E | Post-run log parse correlates each line to its response headers. |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Audit pipeline in crates/waf-engine/src/logging/audit_sender.rs. Durable proof
unset pending `harness-cli story verify`.
