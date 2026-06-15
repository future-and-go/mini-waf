# Exec Plan

## Goal

Persist the existing §6 audit record to a configurable, append-only JSONL file
(`./waf_audit.log`) so the benchmarker can read audit evidence after a run. Close
E12 (US-1201..1204) and unblock E16 US-1603 and the audit-preservation claim of
E10 US-1004.

## Scope

In scope:

- Config field for the audit file path (default `./waf_audit.log`), with enable flag.
- A file sink invoked from the same `AuditSender::send` call sites that previously fed
  VictoriaLogs (`engine.rs:1066` main path, `engine.rs:501` error stub).
- Lazy file creation on first processed request; append-only open mode.
- Ensuring the JSONL `ip` field is the TCP `peer_addr` (not XFF-derived).
- Dropping the `BatchSender` dependency from `AuditSender` and the VL-isms
  (`_msg`/`_time`/`stream`) from the record (the rest of the VL teardown is US-1205).
- Unit + integration tests (file created on first request, one JSON object/line,
  append-only across `reset_state`, `ip` == peer, request_id/mode correlation).

Out of scope (this packet — handled by US-1205 / decision 0010):

- Deleting `vlogs_layer.rs`, `batch_buffer.rs`, the sidecar/installer, the `logs.rs`
  read proxy, and `VictoriaLogsConfig`. This packet stops `AuditSender` from using VL;
  US-1205 removes the now-dead VL code and config.
- Log rotation/retention/compression.
- A `reset_state` marker line (contract MAY; deferred).
- Reworking proxy-path client-IP resolution beyond the audit `ip` field.

## Risk Classification

Risk flags:

- Audit/security (durable security evidence file). **Hard gate.**
- Public contracts (benchmarker reads the file; §6 shape).
- Existing behavior (touches the audit send path).

Hard gates:

- Audit/security → high-risk lane, decision record required (0009 file sink, 0010
  VictoriaLogs decommission).

## Work Phases

1. Discovery — DONE (wiring facts gathered; see design.md citations).
2. Design — DONE (this packet + decisions 0009/0010 accepted; D1–D3 locked).
3. Validation planning — DONE (see validation.md).
4. Implementation — config field, file sink, peer-addr `ip`, wired on send path.
5. Verification — run unit + integration tests; record proof via harness-cli.
6. Harness update — `harness-cli story update`, `harness-cli decision verify`.

## Stop Conditions

Pause for human confirmation if:

- The write mechanism choice (background task vs inline mutex) affects hot-path SLO
  beyond the benchmark's tolerance.
- Making the `ip` field peer-addr-pure would change proxy-path behavior (it must not).
- Config placement requires a breaking change to existing config files.
- Any validation requirement would need weakening.

**Current state: approved and ready to implement — Phases 1–3 done, Phase 4 next.**
