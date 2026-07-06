# GH-198: Redis RiskState Round-Trip Fixes

**Date**: 2026-07-04 23:47
**Severity**: High
**Component**: waf-engine/risk/store (Redis)
**Status**: Resolved (PR #210)

## What Happened

Fixed P1 issue #198: Redis risk store was reporting `is_new=false` for all state applications, breaking risk decision semantics. Root cause: Lua script checked `state_json == nil` to detect missing state, but Redis GET returns boolean `false`, never `nil`. State was always found (even when absent), so new-risk detection never fired. Also corrected decay contributor encoding from `{"Decay":null}` map form to canonical `"Decay"` string—empirical testing revealed serde_json parses both, so the premise "state unparseable" was false. Added first conformance test for decay path coverage and enabled Redis tests in CI via valkey service container.

## The Brutal Truth

Shipped a P1 defect in the Redis store without any CI coverage. The is_new check was broken in plain sight in the Lua script—a simple `== nil` that doesn't work in Lua—and nobody caught it because Redis tests were silently skipped in CI (environment variable gated, no service container). Also wasted effort on a "canonicalization" fix that addressed a non-existent parse failure; the code review caught that the premise was wrong only after implementation. Would have saved time by running a quick serde parse test before framing it as a bug fix.

## Technical Details

- **is_new defect**: `is_new = (state_json == nil)` in crates/waf-engine/src/risk/store/redis_lua.rs always evaluates false because Redis GET returns boolean false on key miss, not nil. Replaced with `is_new = (#candidates == 0)` at owner resolution point—matches MemoryRiskStore mint semantics exactly, including TTL-expired-state-key edge case.
- **Decay encoding**: Changed `kind = {Decay = cjson.null}` to `kind = 'Decay'` in the Lua script. Unit variant canonicalization—serde_json's unit-variant lenient handling accepts both forms, so no parsing failure ever occurred.
- **New conformance test**: `test_decay_contributor_roundtrip` in risk/store/conformance.rs covers memory + Redis decay path (MAX_DECAY + 40 seed, MIN_CLEAN_STREAK application, triggering decay on next contribution). First explicit decay coverage anywhere; uses deterministic now_ms and exported decay constants.
- **CI enablement**: Added valkey/valkey:8-alpine service in .github/workflows/ci.yml, exported REDIS_TEST_URL to test job. First CI run (run 28712967249) executed conformance_redis, redis::tests, redis_failover, device_fp/ddos/rate_limit Redis suites—all passed without code changes.
- **Gotchas**: (1) Lua raw strings r"..." terminate on unescaped double quotes inside Lua comments; use single quotes. (2) clippy nursery too_long_first_doc_paragraph on new test doc. (3) Local test failure: engine::tests::fast_path_exits_skip_risk_scoring fails in sandbox (no docker socket), but passes CI; Redis proof deferred to CI by design.

## Lessons Learned

1. **Verify parse-failure claims before framing fixes**: The decay contributor "bug" was a false positive—tested parsing locally and serde_json accepted both forms. Lesson: don't assume parsing will fail; write a one-line test before calling it a defect.
2. **Gated tests need CI coverage**: Redis tests were marked "skip if no REDIS_TEST_URL" but the variable was never set in CI, so coverage was effectively zero. Environment-gated tests are only real if CI actually provides the resource.
3. **Audit empirically on live defects**: Code review caught the "canonicalization is unnecessary" fact because we actually tested the behavior—would have saved a commit if we'd done that before implementation.

## Next Steps

- PR #210 merged, issue #198 closed.
- Out of scope per plan: #201 (parse-error cache bypass) remains unaddressed.
- Coverage workflow failure on main-harness pre-existing (4.05% < 5% floor), unrelated to this fix.
