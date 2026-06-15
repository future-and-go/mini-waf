---
title: "E12 Audit Log — JSONL file sink + VictoriaLogs decommission"
description: ""
status: completed
priority: P2
branch: "main-harness"
tags: []
blockedBy: []
blocks: []
created: "2026-06-15T08:12:40.798Z"
createdBy: "ck:plan"
source: skill
---

# E12 Audit Log — JSONL file sink + VictoriaLogs decommission

## Overview

Close epic **E12 — Audit Log** (interop v2.3 §6/§8/§10). Make a configurable,
append-only JSONL file (`./waf_audit.log`) the **sole** audit sink, then fully
decommission VictoriaLogs. Lane: **high-risk** (audit/security evidence, public
contract the benchmarker reads, existing-behavior change). Decisions **0009**
(JSONL file sink) and **0010** (VL decommission) are accepted; US-1201 design
decisions **D1–D3** are locked.

Stories closed: US-1201 (JSONL append-only, configurable, first-request),
US-1202 (8 required §6 fields + types), US-1203 (`ip` = TCP `peer_addr`, distinct
`127.0.0.x`, Host validation), US-1204 (request_id/mode ↔ response-header
correlation), US-1205 (remove all VictoriaLogs code + config).

**Key codebase facts (verified):**
- `build_vl_payload` (`audit_sender.rs:107`) already emits all 8 §6 fields plus
  VL-isms (`_msg`/`_time`/`stream`) and FE extras. It ships **only** to
  VictoriaLogs via `BatchSender` — no on-disk file exists. This blocks all of E12.
- `AuditSender::new(buffer: BatchSender)` is wired once in `main.rs` init_async
  (`config.victoria_logs.enabled` gate, ~line 1604). Two send call sites:
  `engine.rs:1021 send_audit_event` (main path) and `engine.rs:470
  emit_minimal_audit_stub` (error path). No new call sites needed.
- `AuditEvent.client_ip` is set from `ctx.client_ip`, which is **trust-resolved**
  (`extract_client_ip_from_session`, XFF-honored when `trust_proxy_headers=true`).
  `RequestCtx` has **no** raw peer field. The raw peer is `peer_addr.ip()` at
  `request_ctx_builder.rs:88`. → US-1203 requires threading the raw peer IP into
  the audit `ip` field (D2), independent of proxy-trust.
- VL surface to remove (US-1205): `vlogs_layer.rs`, `batch_buffer.rs`,
  `crates/prx-waf/src/victoria_logs/*`, `waf-api/src/logs.rs` + its 3 routes +
  `AppState::victoria_logs_base_url` + `logs_streams_cache`, `VictoriaLogsConfig`
  + `[victoria_logs]` block, plus VL wiring in `main.rs`. `db_batch_writer.rs`,
  `/ws/logs`, console logging, `set_log_level` are **untouched**.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Audit file sink + config](./phase-01-audit-file-sink-config.md) | Complete |
| 2 | [Peer-addr IP semantics](./phase-02-peer-addr-ip-semantics.md) | Complete |
| 3 | [Header correlation tests](./phase-03-header-correlation-tests.md) | Complete |
| 4 | [Decommission VictoriaLogs](./phase-04-decommission-victorialogs.md) | Complete |
| 5 | [Verification + harness proof](./phase-05-verification-harness-proof.md) | Complete |

## Dependencies

<!-- Cross-plan dependencies -->
