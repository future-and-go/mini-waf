# US-1201 JSONL append-only to ./waf_audit.log, configurable, created on first request

## Status

implemented

## Lane

high-risk

## Product Contract

The WAF writes structured audit records as JSONL — exactly one valid JSON object
per line — to `./waf_audit.log` at a configurable path (interop v2.3 §6). The log
is append-only and is created once the first request is processed. `reset_state`
MUST NOT delete, truncate, rotate, or rewrite it; a structured event MAY be
appended noting `reset_state` was called (§8). The audit log is SIEM-ingestible
and does not replace the §5 response headers.

## Relevant Product Docs

- `docs/product/audit-log.md`
- interop contract v2.3 §6 (audit log shape), §10 (source-IP trust model)

## Acceptance Criteria

- Every written line is one valid, independently-parseable JSON object (JSONL).
- The audit file is append-only: new records are appended, existing bytes are
  never overwritten, truncated, or rotated by the engine.
- `reset_state` does not delete, truncate, rotate, or rewrite the audit log; it
  MAY append a structured event noting it was called.
- The audit file path is configurable; default is `./waf_audit.log`.
- The file is created once the first request is processed (not at idle startup).

## Design Notes

- Commands: append audit record on each processed request.
- Queries: read-back is a direct parse of `./waf_audit.log`; the VictoriaLogs read
  proxy is removed (US-1205).
- API: writer in `crates/waf-engine/src/logging/audit_sender.rs`.
- Tables: none — flat JSONL file, one JSON object per line.
- Domain rules: append-only; survives `reset_state`; created on first request;
  configurable path.
- UI surfaces: none.

## Validation

When updating durable proof status, use numeric booleans:
`scripts/bin/harness-cli story update --id <id> --unit 1 --integration 1 --e2e 0 --platform 0`.

| Layer | Expected proof |
| --- | --- |
| Unit | Audit record serializes to one valid JSON object per line. |
| Integration | Append-only across `reset_state`; file created on first request, not truncated/rotated. |
| E2E | Post-run parse of `./waf_audit.log` confirms valid JSONL. |
| Platform | |
| Release | |

## Harness Delta

Story registered under decision 0008-interop-contract-v2.3-adoption; durable proof
booleans set via harness-cli after verification.

## Evidence

Audit pipeline in crates/waf-engine/src/logging/audit_sender.rs. Durable proof
unset pending `harness-cli story verify`.
