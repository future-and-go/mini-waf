# GH-250 — geoip-risk P0 test gaps plan validated; false-positive gaps identified

**Date:** 2026-07-06 20:38 +07:00
**Severity:** Medium (plan validation caught inaccuracy in test-gap report)
**Component:** test validation, risk engine test suite
**Status:** RESOLVED (plan created, phases 1–2 real work identified, phases 3 dropped)

## What Happened

Created and validated `plans/260706-2038-geoip-risk-p0-test-gaps/` from the test-scenario catalog report. During validation, discovered that the report's two P0 risk-engine gaps (RSK-SE2: whitelist-vs-canary ordering; RSK-C1: canary→ban-table TTL) were **false gaps** — the corresponding tests already existed in `crates/waf-engine/src/risk/tests/canary.rs`:
- `whitelist_bypasses_canary` 
- `canary_path_triggers_block_and_score_100`
- `canary_pin_expires_after_ttl`

Report also misnamed one test and cited it as absent.

## The Brutal Truth

The test-gap catalog only scanned `tests/*.rs` (integration directory), completely missing the in-crate test module at `src/risk/tests/canary.rs`. This is a silent failure — the report looked thorough but covered only half the test surface. Phase 3 of the plan (addressing RSK-C1) was dropped at validation; a correction note appended to the report.

## Root Cause

Test-gap sweeps must walk `src/**/tests/*.rs` in-crate modules in addition to `tests/` integration test files. The catalog script only checked one directory.

## Validated Decisions

- `configs/geo-rules.yaml` id-4 IR row: `action: challenge` → `block` (challenge unsupported; enforcement unchanged)
- Working-tree edits to `configs/risk.yaml` and `configs/geo-rules.yaml` are temporary and must be reverted
- ~80 KB xdb binary fixture for geoip reload-preserve test is an approved dependency (committed as fallback)
- Redis test scenarios remain owned by `plans/260704-2309-gh-198-redis-riskstate-roundtrip`

## Real Work Remaining

**Phases 1, 2, 4** pending implementation:
- Phase 1: unsupported-action loader fallback test
- Phase 2: geoip reload-preserve service test
- Phase 4: verification gate

---

Status: DONE
Summary: Plan validation identified false-positive gaps in the test-gap report and refined scope; real work scope is phases 1–2 plus verification, with lesson captured for future test catalogs.
