# 0010 Decommission VictoriaLogs

Date: 2026-06-15

## Status

Accepted

## Context

VictoriaLogs was adopted as the WAF's logging backend: a managed in-process sidecar
(`crates/prx-waf/src/victoria_logs/*`), a `tracing → VictoriaLogs` layer
(`vlogs_layer.rs`), the audit network sink (`audit_sender.rs` → `batch_buffer.rs`
`BatchSender` → HTTP), an admin read proxy (`crates/waf-api/src/logs.rs` exposing
`/api/v1/logs/query|stats|streams`), and `VictoriaLogsConfig` in `waf-common`.

Decision 0009 makes a JSONL file (`./waf_audit.log`) the **sole** audit sink, which
is what interop v2.3 §6/§8/§10 and the benchmarker actually require. Once the file
sink lands, VictoriaLogs serves no contract requirement: the audit evidence is on
disk, and the general `tracing → VL` stream plus the admin log views are
operational conveniences, not contract surface. Keeping VictoriaLogs means
maintaining a downloaded binary, a sidecar supervisor, a network transport, and a
loopback read proxy for no contract benefit.

## Decision

Remove VictoriaLogs from the codebase entirely (E12 US-1205):

- **Audit sink** — `AuditSender` drops `BatchSender`; the file sink (US-1201) is the
  only destination. Delete `batch_buffer.rs`.
- **Tracing** — delete `vlogs_layer.rs`; remove the layer registration and pipeline
  wiring from `crates/prx-waf/src/main.rs`. Console (stderr/stdout) logging stays.
- **Sidecar/installer** — delete `crates/prx-waf/src/victoria_logs/*` and its tests;
  drop installer-only dependencies.
- **Read API** — delete `crates/waf-api/src/logs.rs`, its routes, and
  `AppState::victoria_logs_base_url`. `set_log_level` and `/ws/logs` (DB-sourced)
  stay.
- **Config** — remove `VictoriaLogsConfig` and the `[victoria_logs]` block; the
  `[audit]` block (0009) is the only audit configuration.

`db_batch_writer.rs` and the `/ws/logs` websocket are independent of VictoriaLogs
and are not touched.

## Alternatives Considered

1. **Keep VictoriaLogs as a parallel audit/observability backend** — rejected: no
   contract requires it once the file sink exists; the sidecar, network transport,
   and read proxy are ongoing cost and attack surface for a benchmark-scoped WAF.
2. **Remove the audit sink only, keep the tracing layer + read API** — rejected:
   that leaves a half-wired VL stack (sidecar still spawned, config still required)
   with no audit consumer; partial removal is more confusing than full removal.

## Consequences

Positive:

- Single audit transport (the file); no sidecar binary, network sink, or read proxy
  to operate, secure, disk-budget, or keep healthy.
- Smaller dependency and config surface (`flate2`, `tar`, `sha2`, VL `reqwest` use).
- Removes a loopback-only HTTP service and its RBAC/SSRF-guard proxy.

Tradeoffs:

- The admin panel's log-query/stats/streams views lose their backend. Their FE
  surface must be removed or repointed (e.g. to a file reader) — confirm with the
  owner before deleting `logs.rs`.
- General structured-log shipping is gone; operators rely on console logs (and the
  DB-backed `/ws/logs` live stream, which is unaffected).

## Follow-Up

- Sequence after US-1201 lands the file sink (the file must be the audit sink before
  the network sink is deleted).
- Record proof with `harness-cli story update`; register this decision with
  `harness-cli decision add`.
- Resolve the admin log-view FE question before removing `logs.rs`.
