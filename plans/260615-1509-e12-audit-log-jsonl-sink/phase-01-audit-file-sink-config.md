---
phase: 1
title: "Audit file sink + config"
status: completed
priority: P1
effort: "4h"
dependencies: []
---

# Phase 1: Audit file sink + config

## Overview

Add an `[audit]` config block and an `AuditFileSink` that writes the existing §6
audit record as one JSON line per request to a configurable, append-only file
(default `./waf_audit.log`). Re-point `AuditSender` from `BatchSender` to the
file sink. Closes US-1201 and US-1202.

## Requirements

- Functional: file created lazily on first processed request; one valid JSON
  object per line (JSONL); append-only open mode; path configurable; the record
  carries the 8 §6 fields with correct types.
- Non-functional (D1): file I/O kept **off the request hot path** via a dedicated
  single-consumer append task fed by an `mpsc` channel + `BufWriter`, flushed on
  interval and on shutdown. No lock/synchronous write on the send path.

## Architecture

```
engine send_audit_event / emit_minimal_audit_stub
        │  AuditEvent
        ▼
AuditSender::send  ──build_audit_record(event)──►  serde_json::Value
        │  try_send (non-blocking)
        ▼
   mpsc::Sender<String>            (one serialized line, fire-and-forget)
        │
        ▼
  dedicated append task  ──►  BufWriter<File>  (append(true).create(true))
        │  flush on interval + on shutdown
        ▼
   ./waf_audit.log  (JSONL)
```

- New file `crates/waf-engine/src/logging/audit_file_sink.rs`:
  - `AuditFileConfig { enabled: bool, log_path: PathBuf }` consumed here, owned by
    `waf-common` config (see below).
  - `AuditFileSink` holding `mpsc::Sender<String>` + an `is_active` flag.
  - `AuditFileSink::spawn(config) -> AuditFileSink`: opens the file with
    `OpenOptions::new().append(true).create(true)`, spawns the consumer task
    (tokio) owning the `BufWriter`. The first write creating the file = first
    processed request, satisfying US-1201 "created on first request". (Open the
    handle lazily inside the task on first record so an idle process does not
    create the file — matches validation case Integration-1 "absent at idle
    startup". Confirm: open file on first received line, not at spawn.)
  - `append(record: &serde_json::Value)`: `serde_json::to_string(record)? + '\n'`,
    `try_send` to the channel; drop silently if the channel is full/closed so the
    request path is never gated on disk availability (mirrors current
    fire-and-forget VL semantics).
  - Flush: `BufWriter::flush()` on a short interval and on channel close/shutdown.
- `audit_sender.rs`:
  - `Inner { buffer: BatchSender }` → `Inner { sink: AuditFileSink }`.
  - `AuditSender::new(buffer: BatchSender)` → `AuditSender::new(sink: AuditFileSink)`.
  - `send()`: drop the `is_active` early-return semantics onto the sink; build the
    record and `sink.append(&record)`.
  - Rename `build_vl_payload` → `build_audit_record`. Drop the VL-isms `_msg`,
    `_time`, `stream` (dead weight once VL is gone — design "Observability"). Keep
    the 8 §6 fields and the FE-useful extras already present (`event_type`,
    `rule_name`, `rule_id`, `phase`, `host`, `method`, `tier`, `detail`,
    `req_id`, `client_ip`, `query`). Keep `ts_ms` from `timestamp.timestamp_millis()`.
- `crates/waf-common/src/config.rs`:
  - Add `pub struct AuditFileConfig { enabled (default true), log_path (default
    "./waf_audit.log") }` with serde defaults, mirroring sibling config structs.
  - Add `pub audit: AuditFileConfig` to `AppConfig` (the `[audit]` block). Keep
    `victoria_logs` field in place for now — Phase 4 removes it.

## Related Code Files

- Create: `crates/waf-engine/src/logging/audit_file_sink.rs`
- Modify: `crates/waf-engine/src/logging/audit_sender.rs` (sink swap, rename
  builder, drop VL-isms, update unit tests)
- Modify: `crates/waf-engine/src/logging/mod.rs` (export `AuditFileSink`,
  `AuditFileConfig`)
- Modify: `crates/waf-common/src/config.rs` (`AuditFileConfig`, `AppConfig.audit`)
- Modify: `crates/prx-waf/src/main.rs` (construct `AuditFileSink::spawn(&config.audit)`,
  pass to `AuditSender::new`, `engine.set_audit_sender`). Leave VL sidecar/tracing
  wiring untouched here — Phase 4 removes it. Audit sender no longer gated on
  `config.victoria_logs.enabled`; gate on `config.audit.enabled`.
- Modify: `crates/waf-engine/tests/logging_audit_sender.rs` (adapt to file sink;
  may overlap Phase 4 — keep §6 assertions, drop VL-payload assertions)

## Implementation Steps

1. Add `AuditFileConfig` + defaults to `waf-common/config.rs`; add `audit` field
   to `AppConfig`. `cargo build -p waf-common`.
2. Create `audit_file_sink.rs` with `AuditFileSink` (channel + spawned append
   task + `BufWriter`, lazy file open on first line, interval+shutdown flush).
3. Rework `audit_sender.rs`: swap `BatchSender` → `AuditFileSink`, rename
   `build_vl_payload` → `build_audit_record`, drop `_msg`/`_time`/`stream`.
4. Update `audit_sender.rs` unit tests: keep the §6-field / ts_ms / path-includes-
   query / request_id-mirrors-req_id / path-truncation assertions; remove the
   `_time`/`stream` presence assertions.
5. Export new types in `logging/mod.rs`.
6. Wire `main.rs`: build the sink from `config.audit`, pass into `AuditSender::new`.
7. Add unit tests in `audit_file_sink.rs`: (a) `append` writes exactly one line,
   valid JSON, trailing `\n`; (b) two records → two parseable lines; (c) file
   opened append (existing content preserved). Use a `tempfile` working dir.
8. `cargo build -p waf-engine -p prx-waf`; `cargo test -p waf-engine audit`.

## Success Criteria

- [ ] `[audit]` block parses with defaults (`enabled=true`, `log_path=./waf_audit.log`).
- [ ] `AuditSender` holds an `AuditFileSink`, not a `BatchSender`.
- [ ] `build_audit_record` emits the 8 §6 fields with correct types and **no**
      `_msg`/`_time`/`stream`.
- [ ] Unit tests green: one JSON object/line, trailing `\n`, append preserves
      prior content, §6 fields/types asserted.
- [ ] `cargo build -p waf-engine -p prx-waf` succeeds.

## Risk Assessment

- **Hot-path regression** if the write becomes synchronous — mitigated by D1
  (channel + background task; `try_send` non-blocking, silent drop on backpressure).
- **Idle file creation** would fail validation Integration-1 — mitigated by lazy
  open on first received line, not at spawn.
- **Test churn** in `logging_audit_sender.rs` overlaps Phase 4; keep edits to §6
  assertions to avoid rework.
