---
phase: 2
title: Fill test gaps
status: completed
priority: P1
effort: 1h
dependencies:
  - 1
---

# Phase 2: Fill test gaps

## Overview

Add the one missing unit test: `resolve_config_path` in `crates/prx-waf/src/main.rs`.
This function is the literal mechanism of US-1601/US-1602 (cwd config discovery +
hard-fail-on-`run` so the benchmarker never waits on a silently-defaulted WAF), yet
it has no direct test. This is the only code change in the plan.

## Requirements

- Functional: cover all three branches of `resolve_config_path`:
  1. explicit `--config` path wins regardless of `require_cwd`;
  2. cwd discovery finds `waf.yaml` / `waf.yml` / `waf.toml` when present;
  3. `require_cwd = true` (the `run` path) with no config file → `Err` (no hang);
     `require_cwd = false` → falls back to `configs/default.toml`.
- Non-functional: test must not pollute the repo cwd; use a temp dir + `set_current_dir`,
  serialized with a `Mutex` (cwd is process-global), mirroring the env-lock pattern
  already used in `waf-common/tests/config_loader.rs`.

## Architecture

`resolve_config_path(explicit: Option<&str>, require_cwd: bool) -> anyhow::Result<String>`
is a private fn in the binary crate, so the test lives in a `#[cfg(test)] mod` inside
`main.rs` (binary crates cannot expose an integration-test target for private fns).

`#![allow(clippy::print_stdout, clippy::print_stderr)]` is already at the top of
`main.rs`; the test module adds the test-only allows it needs locally.

## Related Code Files

- Modify: `crates/prx-waf/src/main.rs` (append a `#[cfg(test)] mod resolve_config_path_tests`).
- Read for pattern: `crates/waf-common/tests/config_loader.rs` (temp-file + Mutex idiom).

## Implementation Steps

1. Add a `#[cfg(test)] mod resolve_config_path_tests` at the end of `main.rs`.
2. Use a `static CWD_LOCK: Mutex<()>` to serialize `set_current_dir` mutation.
3. Cases:
   - `explicit_path_wins`: `resolve_config_path(Some("x.toml"), true)` → `"x.toml"`.
   - `discovers_cwd_yaml`: in a temp dir containing `waf.yaml`, `resolve_config_path(None, true)`
     → `"waf.yaml"`.
   - `run_without_config_is_error`: in an empty temp dir, `resolve_config_path(None, true)`
     → `Err` (mentions `waf.yaml`/`waf.toml`).
   - `non_run_falls_back_to_default`: empty temp dir, `resolve_config_path(None, false)`
     → `"configs/default.toml"`.
4. Restore the original cwd in each test (guard via the saved `current_dir`).
5. `cargo test -p prx-waf resolve_config_path_tests` → green.

## Success Criteria

- [ ] New unit test module compiles and passes.
- [ ] All four branches asserted; no repo-cwd pollution after the run.
- [ ] `cargo clippy -p prx-waf` clean for the changed file (no new warnings).

## Risk Assessment

- Risk: `set_current_dir` is process-global and races other cwd-touching tests in the
  same binary. Mitigation: the `CWD_LOCK` mutex + save/restore; prx-waf has no other
  cwd-mutating tests today.
- Risk: scope creep into adding boot/integration tests that need Postgres. Mitigation:
  out of scope — US-1601/1602 integration + platform proof is covered by the existing
  suite and the smoke check; do not add a DB-bound boot test here.
