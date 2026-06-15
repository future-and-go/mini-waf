# E12 — Audit Log

Contract: interop v2.3 §6, §10. Product doc: `docs/product/audit-log.md`.
Lane: high-risk (audit/security, data evidence). Code:
`crates/waf-engine/src/logging/audit_sender.rs`.

Structured JSONL to `./waf_audit.log` (configurable), append-only, SIEM-ingestible,
correlated to response headers by `request_id` and TCP source IP. The on-disk
JSONL file is the **sole** audit sink — there is no VictoriaLogs network sink.

VictoriaLogs is fully decommissioned in this epic (decision 0010): the audit
network sink, the `tracing → VictoriaLogs` layer, the managed sidecar/installer,
the `logs.rs` read proxy, and `VictoriaLogsConfig` are all removed.

## Stories

| ID | Title | Lane | Status | §
| --- | --- | --- | --- | --- |
| US-1201 | JSONL append-only to ./waf_audit.log, configurable, created on first request | high-risk | implemented | §6, §8 |
| US-1202 | Required 8 fields + types per entry | high-risk | implemented | §6 |
| US-1203 | `ip` = TCP peer_addr (not XFF); distinct 127.0.0.x clients; Host validation | high-risk | implemented | §6, §10 |
| US-1204 | request_id / mode correlation with response headers | normal | implemented | §6, §5.3 |
| US-1205 | Decommission VictoriaLogs (audit sink, tracing layer, sidecar/installer, read API, config) | high-risk | implemented | §6 |

## Acceptance criteria (per story)

- **US-1201**: one valid JSON object per line; append-only (never truncated/rotated by
  `reset_state`); file path configurable; created once the first request is processed.
- **US-1202**: each line has `request_id` (UUID v4), `ts_ms` (int epoch ms), `ip`,
  `method` (uppercase), `path` (**including query string**), `action` (one of six),
  `risk_score` (0–100), `mode` (enforce/log_only).
- **US-1203**: `ip` is the TCP `peer_addr`/`remote_addr`, never parsed from
  `X-Forwarded-For`/`X-Real-IP`; different `127.0.0.x` aliases are distinct clients for
  rate limit/risk; `Host` validated against expected hostname.
- **US-1204**: `request_id` matches `X-WAF-Request-Id`; `mode` matches `X-WAF-Mode` for
  the same request.
- **US-1205**: no VictoriaLogs code or config remains — `audit_sender` no longer
  references `BatchSender`; `vlogs_layer.rs`, `batch_buffer.rs`, and
  `crates/prx-waf/src/victoria_logs/*` are deleted; the `logs.rs` VL-proxy routes
  (`/api/v1/logs/query|stats|streams`) and `victoria_logs_base_url` state are
  removed; `VictoriaLogsConfig` and the `[victoria_logs]` block are removed; the
  workspace builds and tests green with no VL dependency. The audit file path is
  the only audit configuration. Removal is additive-free: it touches no decision
  logic, only the transport/observability surface.

## Validation shape

Unit: audit-record serialization + field types. Integration: line ↔ header correlation,
peer_addr vs XFF, append-only across `reset_state`. E2E: post-run log parse.
