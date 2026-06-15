---
title: E16 Startup & Binary Contract — verify + close proof
description: >-
  Verify the already-implemented §8 startup contract, fill the one untested unit
  (resolve_config_path), and set durable proof booleans for US-1601/1602/1603.
status: completed
priority: P2
branch: main-harness
tags:
  - E16
  - startup-contract
  - interop-v2.3
blockedBy: []
blocks: []
created: '2026-06-15T14:11:41.539Z'
createdBy: 'ck:plan'
source: skill
---

# E16 Startup & Binary Contract — verify + close proof

## Overview

Epic E16 maps the interop v2.3 §8 startup contract onto the WAF binary:

```text
Binary: ./waf   Start: ./waf run   Config: ./waf.yaml|toml   Logs: ./waf_audit.log
```

**Key finding from scouting: the epic is already code-complete across prior commits.**
This plan is therefore a *verification + proof-closing* effort, not a feature build.
Per CLAUDE.md (Simplicity First, Surgical Changes) it adds the single missing unit
test and records durable proof — nothing more.

### What already exists (verified by reading source)

| Story | Acceptance surface | Where | State |
| --- | --- | --- | --- |
| US-1601 | binary `./waf` | `crates/prx-waf/Cargo.toml` `[[bin]] name="waf"` | ✅ |
| US-1601 | `./waf run` entrypoint | `crates/prx-waf/src/main.rs` `Commands::Run` → `run_server` | ✅ |
| US-1601 | fast-fail on bad config (no hang) | `main.rs:318-327` hard error on `run` | ✅ |
| US-1602 | config from `./waf.yaml|yml|toml` in cwd | `main.rs::resolve_config_path` | ✅ (no unit test) |
| US-1602 | upstream + port from config | `proxy.listen_addr` + `[[hosts]]` in `init_async` | ✅ |
| US-1602 | YAML/TOML parity | `waf-common/src/config.rs::load_config` + `tests/config_loader.rs` | ✅ |
| US-1603 | health 200 when ready | `crates/waf-api/src/health.rs` + `tests/handler_health.rs` | ✅ |
| US-1603 | `./waf_audit.log` lazy on first request | `waf-engine/.../audit_file_sink.rs` (default `./waf_audit.log`) | ✅ |

### The only real gap

`resolve_config_path` (added in commit 97494cf) — the cwd-discovery + hard-fail-on-`run`
logic that is the literal mechanism of US-1601/US-1602 — has **no unit test**. That is
the one code change this plan makes.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Verify existing implementation](./phase-01-verify-existing-implementation.md) | Completed |
| 2 | [Fill test gaps](./phase-02-fill-test-gaps.md) | Completed |
| 3 | [Update durable proof](./phase-03-update-durable-proof.md) | Completed |

## Dependencies

- Decision `0008-interop-contract-v2.3-adoption` (stories registered under it).
- No cross-plan blockers. E12 (audit JSONL sink) is closed and supplies the
  `AuditFileSink` US-1603 depends on.
