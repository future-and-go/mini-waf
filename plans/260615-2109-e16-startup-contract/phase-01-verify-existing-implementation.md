---
phase: 1
title: Verify existing implementation
status: completed
priority: P1
effort: 1h
dependencies: []
---

# Phase 1: Verify existing implementation

## Overview

Confirm the §8 startup contract surfaces compile and the existing targeted tests
pass before changing anything. This grounds the proof claims in Phase 3.

## Requirements

- Functional: workspace builds; health/config/audit tests pass.
- Non-functional: no source changes in this phase (read + run only).

## Architecture

The startup contract spans three crates:

- `crates/prx-waf/src/main.rs` — CLI parse, `resolve_config_path`, `run_server`,
  `init_async` (DB connect → engine → audit sink → host router → listeners).
- `crates/waf-api/src/health.rs` — `GET /health` returns 200 when DB acquires.
- `crates/waf-engine/src/logging/audit_file_sink.rs` — lazy `./waf_audit.log`.

## Related Code Files

- Read: `crates/prx-waf/src/main.rs`
- Read: `crates/waf-common/src/config.rs`, `crates/waf-common/tests/config_loader.rs`
- Read: `crates/waf-api/src/health.rs`, `crates/waf-api/tests/handler_health.rs`
- Read: `crates/waf-engine/src/logging/audit_file_sink.rs`

## Implementation Steps

1. Build the binary crate to confirm the contract compiles:
   `cargo build -p prx-waf` (release not required for verification).
2. Run the existing unit/integration tests that back the contract:
   - `cargo test -p waf-common --test config_loader` (US-1602 YAML/TOML parity).
   - `cargo test -p waf-engine --test audit_file_sink_integration` (US-1603 audit).
   - `cargo test -p waf-engine --lib logging::audit_file_sink` (lazy-create unit).
   - `cargo test -p waf-api --test handler_health` (US-1603 health 200) — note this
     test needs the test DB the suite already provisions; if it cannot connect,
     record that as an environment limitation, not a contract failure.
3. Confirm packaging reconciliation: `[[bin]] name = "waf"` and Dockerfile copies
   `target/release/waf` → `/usr/local/bin/waf` (binary-name half of US-1602 note).

## Success Criteria

- [ ] `cargo build -p prx-waf` succeeds.
- [ ] `config_loader` and `audit_file_sink` tests pass (or DB-dependent ones are
      explicitly noted as env-limited).
- [ ] Binary name `waf` confirmed against the `./waf` contract surface.

## Risk Assessment

- Risk: `handler_health` requires a live test DB. Mitigation: it is an existing
  test, not new scope; note env limitation rather than weakening the assertion.
