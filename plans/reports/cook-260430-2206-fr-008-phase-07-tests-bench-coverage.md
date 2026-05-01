# FR-008 Phase-07 — Cook Report

**Plan:** `plans/260429-2237-fr-008-whitelist-blacklist/phase-07-tests-bench-coverage.md`
**Mode:** `--auto`
**Branch:** `main`
**Date:** 2026-04-30

## Outcome
Phase-07 verification gates met. Bench + AC-08 integration test added. access/** coverage 92.53% (≥90% target). Pingora-driven E2E deferred to phase-07b, mirroring FR-001 phase-06b precedent.

## Changes

| File | Type | Notes |
|---|---|---|
| `crates/waf-engine/benches/access_lookup.rs` | new | Criterion bench, v4+v6 at 1/100/10k entries |
| `crates/waf-engine/Cargo.toml` | modify | register `[[bench]] name = "access_lookup"` |
| `crates/waf-engine/tests/access_reload_under_load.rs` | new | AC-08: 16-thread concurrent readers + mid-flight YAML rewrite + `poll_until` swap visibility |
| `crates/waf-engine/src/access/reload.rs` | modify | +6 unit tests for `WatcherError` Display/Source/From, `spawn` parent guard, `reload()` success/fail paths |
| `plans/.../phase-07-tests-bench-coverage.md` | modify | mark complete, annotate deferrals |

## Verification

- `cargo test -p waf-engine` → **246 unit + 7 integration passed, 0 failed**
- `cargo test -p gateway` → **119 passed, 0 failed** (no regression)
- `cargo clippy -p waf-engine --all-targets --all-features -- -D warnings` → clean
- `cargo fmt --all -- --check` → clean
- `cargo bench --bench access_lookup --quick`:
  - `access_lookup_v4_10000` ≈ **30.8 ns** (target: p99 ≤ 2 µs) ✅
  - `access_lookup_v6_10000` ≈ **88.4 ns** (target: ≤ 4 µs) ✅
  - v4_1 ≈ 14.7 ns, v4_100 ≈ 15.0 ns, v6_1 ≈ 73.9 ns, v6_100 ≈ 89.0 ns
- `cargo llvm-cov` (scoped to access/**):
  - **TOTAL 92.53% lines** (≥90% gate met)
  - config 95.39 / evaluator 97.93 / host_gate 93.55 / ip_table 85.54 / reload 87.31

## AC Coverage Map

| AC | Status | Where verified |
|---|---|---|
| AC-01 v4 blacklist → 403 | ✅ | `evaluator.rs::t_blacklist_v4_blocks` + `access_phase.rs::gate_evaluate_blacklist_blocks` |
| AC-02 v6 blacklist → 403 | ✅ | `evaluator.rs::t_blacklist_v6_blocks` |
| AC-03 longest-prefix wins | ✅ | `ip_table.rs::t_longest_prefix_wins` |
| AC-04 empty lists disabled | ✅ | `evaluator.rs::t_continue_no_lists`, `t_host_gate_disabled` |
| AC-05 host gate per-tier | ✅ | `host_gate.rs::t_per_tier_isolation`, `evaluator.rs::t_host_gate_pass/block` |
| AC-06 tier mode bypass vs continue | ✅ | `evaluator.rs::t_whitelist_full_bypass`, `t_whitelist_blacklist_only` |
| AC-07 bad YAML keeps prior | ✅ | `tests/access_hot_reload.rs::t_reload_bad_yaml_keeps_prior` + `reload.rs::t_reload_keeps_prior_on_bad_yaml` |
| AC-08 reload under load no drops | ✅ | `tests/access_reload_under_load.rs::t_reload_under_load_no_drops` |

## Deferrals

**Pingora E2E suite (5 `gateway/tests/access_e2e_*.rs` files):** deferred to phase-07b per the same blocker that pushed FR-001's E2E to phase-06b — no `WafEngine` test seam that avoids a live PostgreSQL `Database`. The AC contract is already covered at the gateway layer by `pipeline/access_phase.rs::tests` (translates `AccessDecision` → 403/Bypass/Continue) and the engine-level `evaluator.rs::tests`. Re-evaluate when FR-001 phase-06b's harness lands.

**CI coverage-gate script:** not added — out of scope for one phase, project lacks a `scripts/coverage-gate.sh` precedent. Wire after phase-08 docs land.

## Unresolved Questions
- None blocking. Open architectural call: when phase-06b harness lands, wire phase-07b E2E using the same fixtures pattern, OR collapse phase-07b into phase-06b sweep.
