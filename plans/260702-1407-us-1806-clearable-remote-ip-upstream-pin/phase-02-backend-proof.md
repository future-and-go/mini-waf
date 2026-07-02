---
phase: 2
title: "Backend proof"
status: pending
effort: "S"
---

# Phase 2: Backend proof

## Overview

No backend production code changes. Add one repo test proving the empty-string
clear path so the fix is regression-locked, matching the story's Unit/Integration
proof expectations.

## Related Code Files

- Modify: `crates/waf-storage/tests/repo_hosts.rs` (add one `#[tokio::test]`)
- Reference (no change): `crates/waf-storage/src/repo.rs:93-142` (`update_host`),
  `crates/gateway/src/proxy.rs:468-475` (upstream selection)

## Implementation Steps

1. In `repo_hosts.rs`, follow the existing `update_partial_fields_persists`
   pattern (line 85) using the `PgFixture`/`fresh()` harness:
   - Create a host with `remote_ip: Some("10.0.0.9".into())`.
   - `update_host(id, UpdateHost { remote_ip: Some("".into()), ..default })`.
   - Assert `updated.remote_ip == Some(String::new())` — proves
     `COALESCE('', remote_ip)` sets the column to empty (the effective pin is
     cleared, since `proxy.rs:473` filters empty → falls back to `remote_host`).
   - Optionally a second update with `remote_ip: None` and assert the value is
     unchanged (proves NULL keeps old value — documents why the FE must send
     `""`, not omit the field).

2. Do **not** drop `COALESCE($8, remote_ip)`. Empty-string clear is the chosen
   contract (story Design Notes). Leaving COALESCE preserves partial-update
   semantics for every other caller.

## Success Criteria

- [ ] New test in `repo_hosts.rs`: `remote_ip: Some("")` results in stored
  empty string (effective pin cleared).
- [ ] `cargo test -p waf-storage --test repo_hosts` passes (requires the
  Postgres testcontainer harness the suite already uses).
- [ ] No production `.rs` file changed.

## Risk Assessment

- **Test DB availability:** the suite uses `start_postgres` (testcontainers). If
  Docker is unavailable in the runner, the test is a clean skip — record proof
  status honestly rather than faking it (story: `harness-cli` absent in this
  checkout).
- **Proxy unit test for fallback:** the selection expression at `proxy.rs:470`
  is inline in `upstream_peer` and not unit-testable without a pingora session.
  Extracting a helper would be a non-surgical change for a trivial expression;
  the integration test in phase 3 covers the fallback instead. Note this
  deviation from the story's Unit row (proxy fallback proven at integration, not
  unit).
