# Design

## Domain Model

One **audit record** per processed request — the §6 JSON object already produced by
`build_vl_payload` in `crates/waf-engine/src/logging/audit_sender.rs`. Required
fields: `request_id`, `ts_ms`, `ip`, `method`, `path` (incl. query), `action`,
`risk_score`, `mode`. Extra fields allowed (must carry no secrets — current payload
carries none).

## Application Flow

Audit send is already centralized. Two call sites construct an `AuditEvent` and call
`AuditSender::send`:

- `crates/waf-engine/src/engine.rs:1066` — `send_audit_event()`, main decision path
  (from `inspect()` at `engine.rs:638`).
- `crates/waf-engine/src/engine.rs:501` — `emit_minimal_audit_stub()`, error path.

`AuditSender` is constructed once at `crates/prx-waf/src/main.rs:1626`:
`engine.set_audit_sender(Arc::new(AuditSender::new(batch_sender)))`.

Plan: replace `AuditSender`'s `BatchSender` with an **`AuditFileSink`**. `send()`
writes the same §6 record to the file. The VictoriaLogs network sink is removed
(US-1205), so the file is the only destination. No new call sites — both existing
sites (`engine.rs:1066`, `engine.rs:501`) keep working unchanged.

## Interface Contract

The VL-proxy HTTP routes (`/api/v1/logs/query|stats|streams`) are removed with the
read API (US-1205); no other HTTP routes change. Internal:

- `AuditSender::new(buffer: BatchSender)` → `AuditSender::new(file_sink: AuditFileSink)`
  (or a builder), wired from `main.rs` using the new audit config. The `BatchSender`
  parameter is dropped.
- `AuditFileSink::append(record: &serde_json::Value)` — serializes the record with
  `serde_json::to_string` + `'\n'`, appends one line.

## Data Model

Flat JSONL file, default `./waf_audit.log`, one JSON object per line. No DB tables.
Open with `OpenOptions::new().append(true).create(true)` — append-only, created on
first write (= first processed request, satisfying US-1201). Path resolved relative
to the process working directory per §8.

## UI / Platform Impact

CLI/deployment only: the file appears in the WAF working directory. No browser/mobile.

## Observability

This *is* the audit observability surface — and, after US-1205, the only one. The
`_msg`/`_time`/`stream` VL-isms in the current payload become dead weight once
VictoriaLogs is gone; drop them and emit a §6-only object (the field builder is
renamed off `build_vl_payload`). Removing the VL-isms is in scope here so the
decommission leaves no VL vocabulary behind.

## Locked Decisions

Approved 2026-06-15 — ready to implement.

### D1 — Write mechanism — LOCKED: A

Dedicated single-consumer append task fed by an `mpsc` channel + `BufWriter`,
flushed on interval and on shutdown. Keeps file I/O off the request hot path. The
inline `Mutex<BufWriter<File>>` alternative (B) was rejected to avoid adding a lock +
synchronous write to the hot path.

### D2 — `ip` field = TCP peer_addr (§6/§10) — LOCKED: A

Thread the raw `peer_addr` (already computed at `request_ctx_builder.rs:107`) into
`AuditEvent` and use it for the JSONL `ip` field. Contract-pure regardless of
`trust_proxy_headers`; does not change proxy-path routing behavior, only what the
audit `ip` field reports. The "rely on `trust_proxy_headers = false`" alternative (B)
was rejected as ambiguous under proxy-trust configs.

### D3 — Config placement — LOCKED

New minimal block `[audit] enabled=true, log_path="./waf_audit.log"` →
`AuditFileConfig` on `AppConfig`. The old `[victoria_logs]` block / `VictoriaLogsConfig`
is removed entirely (US-1205), so there is no VL block to attach to — a standalone
`[audit]` block is the only option.

## Alternatives Considered

1. **Keep VictoriaLogs as a parallel sink** — rejected: the decommission decision
   (0010) removes VL outright; §6 + the benchmarker require reading `./waf_audit.log`
   on local disk, and a network sink no longer earns its operational cost.
2. **Write the file in `logs.rs` read API** — moot: `logs.rs` is the VL read proxy
   and is deleted in US-1205; the writer belongs at the existing send call sites
   regardless.
3. **Tee at the `BatchSender` layer** — moot: `BatchSender` is deleted with the VL
   network transport (US-1205). The sink lives in `AuditSender`.
