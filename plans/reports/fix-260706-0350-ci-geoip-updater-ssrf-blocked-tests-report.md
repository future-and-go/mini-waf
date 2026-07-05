# Fix Report — main-harness CI round 2 (run 28753336001): geoip updater tests vs SSRF-hardened client

**Date:** 2026-07-06 | **Branch:** main-harness | **Confidence:** high (all claims empirically verified)
**Predecessor:** `fix-260706-0013-ci-engine-risk-tests-and-redis-outage-flake-report.md` (round 1, committed 87ca279/10e8997)

## Symptom

After round-1 fixes went green through the lib suite, CI reached `tests/geoip_updater_schedule.rs` for the first time and failed 2 tests:

1. `check_update_returns_true_when_remote_size_differs` — expected `true`, got `false` path panic: `update: URL failed SSRF validation`
2. `update_is_noop_when_check_update_returns_false` — same SSRF validation error via `update()`

## Root Cause (test-only; production code + security posture correct)

- Both tests require a **successful HEAD request against a loopback wiremock server** through the public `check_update()`/`update()` API.
- Since SSRF hardening (c6481a0), `validated_fetch::build_validated_client` rejects loopback/private/reserved/IMDS base URLs **by design** (unit-tested in `validated_fetch.rs`). A local mock server is therefore unreachable through the public API — the tests assert a scenario the security model forbids.
- **Why now:** the tests merged while main-harness CI was red; cargo's fail-fast stopped earlier failing binaries from letting this one run. Round 1 turned the lib suite green, so this binary executed for the first time in run 28753336001. Never green before.

## Fix (does NOT weaken SSRF validation — hard gate honored)

- `crates/waf-engine/src/geoip_updater.rs`: split `check_update` into the public fn (missing-file early return **before** any client build/network, then builds the validated client) and private `check_update_with(&self, client)` — the same injectable-client seam `download_one` already uses. Public behavior byte-identical.
- Added 2 unit tests driving the seam at wiremock via the existing `production_shaped_client()` helper: `check_update_with_returns_false_when_sizes_match`, `check_update_with_returns_true_on_size_mismatch` — restores real coverage of the size-comparison branch.
- `crates/waf-engine/tests/geoip_updater_schedule.rs`: replaced the two impossible tests with `check_update_missing_file_short_circuits_before_network` (mock has `.expect(0)` — proves the missing-file branch decides without any HEAD) + comments explaining why a successful loopback HEAD cannot be exercised through the public API and where the coverage lives instead.

## Verification (fresh evidence)

- `cargo test -p waf-engine --test geoip_updater_schedule` → **18 passed; 0 failed**.
- `cargo test -p waf-engine --lib -- geoip_updater` → **19 passed; 0 failed**.
- `cargo fmt -p waf-engine -- --check` clean; `cargo clippy -p waf-engine --all-features --all-targets` clean.
- **Full-workspace fail-fast landmine sweep** (`cargo test --workspace --all-features --no-fail-fast`, PG+Redis env): 137 suites / 1812 tests passed. 57 suites failed locally — every one classified:
  - 56 panic at testcontainer startup (`docker socket PermissionDenied`) in `tests/common/mod.rs` of waf-api (30), waf-storage (15), waf-engine (11) — local docker permission only; CI provisions docker and these suites are green there.
  - `config_yaml_regression` fails only against the locally-corrupted `configs/*.yaml` (open debug task evidence): stash → **7 passed; 0 failed** → pop.
  - **Conclusion: no further real regressions hide behind fail-fast.**
- Sweep was blocked mid-way by disk exhaustion (root fs 100%, `target/` = 290G) causing linker failures; freed 61G by deleting `target/debug/incremental`, reran clean.

## Prevention

- Size-comparison branch now has honest, hermetic unit coverage (mirrors `download_one` pattern) instead of tests that only passed via an accidental early return.
- Comments in the integration file stop future contributors from re-adding loopback-HEAD tests that SSRF hardening forbids.

## Commit scope

`crates/waf-engine/src/geoip_updater.rs`, `crates/waf-engine/tests/geoip_updater_schedule.rs`, this report, journal entry. Working tree still carries unrelated `configs/*.yaml` corruption evidence (open debug task) — **MUST be excluded**.

## Code review

code-reviewer: DONE_WITH_CONCERNS, non-blocking. Verified behavior of `check_update` provably unchanged (line-level diff vs HEAD), SSRF gate untouched, both size-comparison branches genuinely covered. Applied its one pre-commit action (stale test-file header line). Deferred follow-up (pre-existing, not from this diff): the `Ok(resp)` non-success HEAD arm has phantom coverage only — `check_update_head_non_success_continues_to_next_file` never reaches it (missing-v6 early return fires first); now trivially coverable via the new `check_update_with` seam (mount 404 for v4 + matching content-length for v6, assert `Ok(false)`).

## Unresolved questions

- `configs/challenge.yaml` / `device-fp.yaml` / `risk.yaml` corruption (admin-panel write path) still awaits user decisions from `debug-260705-2331-ddos-config-schema-mismatch-risk-save-report.md`.
