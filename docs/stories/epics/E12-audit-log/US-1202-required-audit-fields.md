# US-1202 Required 8 fields + types per entry

## Status

implemented

## Lane

high-risk

## Product Contract

Each audit log entry MUST carry the eight required fields with the exact types and
constraints defined by interop v2.3 §6. Extra JSON fields are allowed but MUST NOT
weaken the required fields and MUST NOT contain secrets, credentials, session
tokens, stack traces, or other sensitive data. One valid JSON object per line is
preserved.

## Relevant Product Docs

- `docs/product/audit-log.md`
- interop contract v2.3 §6 (required fields + types), §10 (source-IP trust model)

## Acceptance Criteria

- `request_id` — string, UUID v4; MUST match `X-WAF-Request-Id` when both present.
- `ts_ms` — int, Unix epoch milliseconds.
- `ip` — string, TCP peer address in IPv4 dotted decimal (NOT XFF).
- `method` — string, uppercase HTTP method.
- `path` — string, request path **including query string**.
- `action` — string, one of the six decision classes (§3).
- `risk_score` — int, range 0–100, score at decision time.
- `mode` — string, `enforce` or `log_only`; MUST match `X-WAF-Mode` when present.
- Extra fields MUST NOT weaken required fields or carry secrets/credentials/session
  tokens/stack traces/sensitive data.

## Design Notes

- Commands: serialize each decision into an audit record with all 8 fields.
- Queries: read-back is a direct parse of `./waf_audit.log` (benchmarker / tests);
  the VictoriaLogs read proxy is removed (US-1205).
- API: record struct + serialization in
  `crates/waf-engine/src/logging/audit_sender.rs`.
- Tables: none — JSONL, one JSON object per line.
- Domain rules: 8 required fields with fixed types; `path` includes query string;
  `risk_score` clamped 0–100; `mode` in {enforce, log_only}.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Audit-record serialization emits all 8 fields with correct types and ranges. |
| Integration | Line-to-header correlation confirms `request_id`/`mode` field values. |
| E2E | Post-run log parse validates every line carries the 8 required fields. |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Audit pipeline in crates/waf-engine/src/logging/audit_sender.rs. Durable proof
unset pending `harness-cli story verify`.
