# main-harness CI round 2: geoip updater tests demanded what SSRF hardening forbids

**Date:** 2026-07-06 03:50 +07:00
**Severity:** Medium (CI red on main-harness, second consecutive red run)
**Component:** waf-engine (geoip_updater + integration tests)
**Status:** COMPLETE (fix verified locally, awaiting commit)

## What Happened

Round 1 (see `2026-07-06-ci-main-harness-risk-test-fixes.md`) turned the waf-engine lib suite green — which let CI reach `tests/geoip_updater_schedule.rs` for the first time ever. Two tests failed immediately: both required a successful HEAD request against a loopback wiremock server through `check_update()`/`update()`, which the SSRF-validated client (`validated_fetch::build_validated_client`, commit c6481a0) rejects by design. The tests were merged while CI was red; cargo fail-fast had hidden them behind earlier failures.

Fix: gave `check_update` the same injectable-client seam `download_one` already had (`check_update_with`), moved size-comparison coverage into hermetic unit tests using the `production_shaped_client()` helper, and replaced the impossible integration tests with one that proves the missing-file branch short-circuits before any network I/O (`.expect(0)` mock). SSRF validation untouched.

## The Brutal Truth

1. **Fail-fast is a landmine dispenser.** Two rounds in a row, "fix the red tests" surfaced a fresh batch of never-executed tests. So this round I refused to declare done without a full `--no-fail-fast` workspace sweep.
2. **The sweep hit disk exhaustion.** Root fs was 100% full (`target/` had grown to 290G across sessions); waf-api test binaries failed to link with cryptic `cc` errors. Deleting `target/debug/incremental` (61G) unblocked it. Linker "errors" that are really ENOSPC waste real time.
3. **57 suites fail locally and that's fine** — all classified, none real: 56 are testcontainer startups denied by the local docker socket (CI has docker), 1 is `config_yaml_regression` tripping on the locally-corrupted `configs/*.yaml` evidence from the open admin-panel debug task (stash → 7/7 pass → pop).
4. **Slow classification loops get killed.** Rerunning failing suites through cargo one-by-one blew the 10-minute window. Running the already-built test binaries directly finished all 57 in seconds.

## Evidence

- Integration suite: 18 passed / 0 failed; lib geoip_updater tests: 19 passed / 0 failed.
- fmt + clippy clean.
- Workspace sweep: 137 suites / 1812 tests passed; all 57 local failures classified environmental (above).

## Lessons

- A test that only ever passed via an accidental early return (missing v6 file short-circuiting before the mock was contacted) is worse than no test: it documents behavior the system forbids.
- When tests demand network shapes security hardening forbids, the answer is an injectable seam mirroring the existing pattern — never a validation carve-out.
- After any red-CI fix, sweep the whole workspace with `--no-fail-fast`; the default mode systematically under-reports.

Report: `plans/reports/fix-260706-0350-ci-geoip-updater-ssrf-blocked-tests-report.md`
