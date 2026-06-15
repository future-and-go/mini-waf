# E16: Startup & Binary Contract — Config Path Resolution Unit Test Gap Closed

**Date:** 2026-06-15
**Severity:** Medium
**Component:** Configuration loading, startup flow, binary contract
**Status:** Closed

## What Happened

Epic E16 (Startup & Binary Contract v2.3 §8) was code-complete from prior commits. This was pure verify + test-gap-fill + proof-closing: no feature build. The single real gap was missing unit test coverage for `resolve_config_path` in `crates/prx-waf/src/main.rs`. Added 4-case test suite; reconciled epic README and 3 story files from in_progress → implemented; set durable proof via harness-cli. Commit b62a8d2 on main-harness (not pushed).

## The Brutal Truth

Honoring Simplicity-First meant resisting the urge to refactor adjacent code or add new behavior. The epic was done; we just needed to verify it and fill the one gap. One real friction: `cargo build` is hook-blocked in this env, so verification had to lean on `cargo check` and `cargo test`. Also, `handler_health` (the health-200 half of US-1603) couldn't execute — Postgres testcontainer needs Docker, not available here — recorded as env-limited, NOT a regression.

## Technical Details

**Config path resolution contract (now tested):**
- Explicit `--config /path/to/file` wins all else
- `run` subcommand (require_cwd=true) hard-fails on missing config so the benchmarker never hangs
- `yaml`, `yml`, `toml` auto-discovery in cwd in priority order
- Non-run falls back to `configs/default.toml`

**Test implementation (4 cases, all green):**
1. Explicit --config flag precedence
2. CWD discovery of waf.yaml / waf.yml / waf.toml (each file type tested)
3. `run` subcommand failure on missing config (hard-fail contract)
4. Default fallback for non-run commands

**Isolation strategy — static CWD_LOCK mutex + RAII CwdGuard:**
- Prevents process-global cwd mutation race between parallel tests
- Drop order: restore cwd → remove tempdir → release lock
- Added `tempfile = "3"` as dev-dependency

**Proof reconciliation (durable, via harness-cli story update):**
- US-1601 (config path resolution): unit=1
- US-1603 (audit file sink + health): unit=1 + integration=1 (lazy-creates `./waf_audit.log` on first event)
- US-1602 (audit sink read): left at prior unit=1/platform=1 (sticky-proof — did not downgrade existing verified proof)
- Epic README + 3 story files: in_progress → implemented

**Verification run (21/21 green):**
- 4 resolve_config_path tests
- 9 config_loader tests
- 5 audit_file_sink_integration tests
- 3 audit_file_sink unit tests
- code-reviewer sign-off: surgical changes, branch coverage complete, drop-order sound, no plan-artifact references in comments

## Lessons Learned

**Config path logic was complete, but test coverage gap invited silent failure.** A future change to CWD behavior or fallback order could ship untested. Test-first would have caught this earlier.

**Process-global state (cwd) in unit tests requires explicit isolation.** Mutex + RAII guard pattern prevents flaky tests from cross-talk; drop order matters.

**Env-limited proof is not a regression.** Postgres testcontainer unavailability is infrastructure, not a code defect. Recorded as such; left e2e/platform at 0 rather than faking pass.

## Next Steps

None — E16 closed. Proof durable. Contract verified. Ready for main merge (awaiting lead decision on push).

**Proof:** 21/21 targeted tests green; `cargo check` + `cargo test` clean; harness-cli story proof updated; code-reviewer approved.
