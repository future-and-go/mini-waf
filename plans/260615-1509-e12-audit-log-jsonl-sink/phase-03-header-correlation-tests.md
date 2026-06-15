---
phase: 3
title: "Header correlation tests"
status: completed
priority: P2
effort: "3h"
dependencies: [1, 2]
---

# Phase 3: Header correlation tests

## Overview

Prove the audit line correlates to the response headers: line `request_id` ==
`X-WAF-Request-Id` and line `mode` == `X-WAF-Mode` for the same request, plus the
append-only and first-request invariants end-to-end. Closes US-1204 and supplies
the integration proof for US-1201..1203. Mostly tests — the data already flows
(E11 headers `implemented`, `AuditEvent` carries `req_id` and `mode`).

## Requirements

- Functional: for a single processed request, the JSONL line's `request_id` and
  `mode` equal the corresponding `X-WAF-Request-Id` / `X-WAF-Mode` response
  headers. Append-only holds across `reset_state`.
- Non-functional: tests deterministic (temp cwd, isolated `./waf_audit.log`,
  injected/fixed clock where feasible).

## Architecture

Integration tests live where the existing interop/control-plane integration
tests live (`crates/waf-api/tests/` and/or `crates/waf-engine/tests/`). Drive a
request through the proxy/engine, capture the response headers, then parse the
audit file's last line and assert field equality.

Correlation source of truth:
- `X-WAF-Request-Id` ← `req_id`; audit `request_id` ← `req_id` (same value).
- `X-WAF-Mode` ← `InteropMode`; audit `mode` ← `mode.as_contract_str()`.

## Related Code Files

- Create/Modify: `crates/waf-engine/tests/logging_audit_sender.rs` or a new
  `crates/waf-api/tests/audit_log_correlation.rs` (follow existing
  `interop_control_integration` harness in `waf-api/tests`)
- Read for context: `crates/waf-api/tests/common/mod.rs` (test server harness),
  the E11 header-writing path (`proxy_waf_response_writer`)

## Implementation Steps

1. Locate the existing integration harness that boots the engine/proxy with a
   temp config (reuse `interop_control_integration` patterns).
2. Test: **first-request creation** — assert `./waf_audit.log` absent at idle
   start, present with ≥1 line after the first request.
3. Test: **N requests → N parseable lines** (each `serde_json::from_str` ok, 8 §6
   fields present).
4. Test: **append-only across reset_state** — capture file bytes, call
   `reset_state`, assert file length unchanged / not truncated, then a further
   request appends a new line.
5. Test: **header correlation** — capture `X-WAF-Request-Id` + `X-WAF-Mode` from
   the response, assert they equal the audit line's `request_id` / `mode`.
6. Test: **distinct peers** — drive from `127.0.0.1` and `127.0.0.2`; assert two
   lines with distinct `ip`.
7. `cargo test -p waf-api interop_control` (and the new test module).

## Success Criteria

- [ ] File absent at idle, created on first request.
- [ ] N requests → N valid JSON lines, all with the 8 §6 fields.
- [ ] Append-only verified across `reset_state` (byte-length / not-truncated).
- [ ] `request_id` == `X-WAF-Request-Id` and `mode` == `X-WAF-Mode` for the same
      request.
- [ ] Two `127.0.0.x` aliases → distinct `ip` values.
- [ ] Integration tests green.

## Risk Assessment

- **reset_state truncating the file** would fail append-only — the file sink
  never references `reset_state`; assert explicitly. If a `reset_state` marker
  line is ever added later, it must be an append, not a rewrite.
- **Flaky cwd / shared file** between tests — mitigated by per-test temp working
  dir; never assert against a shared `./waf_audit.log`.
