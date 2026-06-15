# Overview

High-risk packet for the `./waf_audit.log` JSONL file writer. This is the missing
implementation slice underpinning all of E12 (US-1201..1204): the §6 audit record
schema is already built, but it is only shipped to VictoriaLogs over the network —
there is no on-disk JSONL file for the benchmarker to read.

The file becomes the **sole** audit sink: the VictoriaLogs network sink is removed,
not run in parallel (see US-1205 / decision 0010 for the full decommission).

## Current Behavior

- `crates/waf-engine/src/logging/audit_sender.rs` builds the contract §6 JSON
  object (`build_vl_payload`) with all required fields (`request_id`, `ts_ms`,
  `ip`, `method`, `path` incl. query, `action`, `risk_score`, `mode`).
- `AuditSender::send` forwards that object to a `BatchSender` (`batch_buffer.rs`),
  which POSTs batches to VictoriaLogs over HTTP. **Network sink only — no file I/O.**
- No file named `./waf_audit.log` is ever created or written.
- `reset_state` (`crates/waf-api/src/interop_control.rs:110`) already returns
  `audit_log_preserved: true` and touches no audit state.

## Target Behavior

- Each processed request appends exactly one valid JSON object (one line) to a
  configurable audit file, default `./waf_audit.log`.
- File is created lazily on the first processed request (not at idle startup).
- Append-only: existing bytes never overwritten, truncated, or rotated by the engine.
- `reset_state` does not delete/truncate/rotate/rewrite the file (preserved by
  construction — the reset path never references the writer).
- The `ip` field is the TCP `peer_addr`, never XFF-derived (§6/§10).
- `request_id` and `mode` in each line match `X-WAF-Request-Id` / `X-WAF-Mode` for
  the same request (already true in the payload builder).

## Affected Users

- Benchmark harness / SIEM consumers reading `./waf_audit.log` after a run.
- WAF operators relying on durable local audit evidence.

## Affected Product Docs

- `docs/product/audit-log.md`
- interop contract v2.3 §6 (audit shape), §8 (paths), §10 (source-IP trust)

## Non-Goals

- Log rotation, compression, or retention management.
- Reworking client-IP resolution for the proxy data path (only the audit `ip`
  field is made peer-addr-pure).
- Appending a `reset_state` marker line (contract MAY, deferred).
- The broader VictoriaLogs decommission (tracing layer, sidecar, read API) — that
  is US-1205 / decision 0010. This packet only replaces the audit *sink* with the
  file writer; US-1205 removes the now-dead VL code.
