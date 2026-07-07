# Risk Config Admin UI E2E Suite: 35/35 Green, Two Product Gaps Surfaced

**Date**: 2026-07-07 14:21
**Severity**: High (gaps discovered), Medium (test suite delivery)
**Component**: Risk Scoring Engine config API, Admin UI E2E
**Status**: Resolved (suite complete; product gaps documented, not fixed)

## What Happened

Executed the full 5-phase risk config E2E plan (plans/260707-1035-risk-config-admin-ui-e2e-verification/). Built a deterministic verification suite covering all 12 UI-exposed risk settings: 35/35 tests passing. Delivered:
- `tests/e2e/run-risk-config.sh` (persistence round-trips, deep-merge, behavioral groups)
- Fixtures: risk.yaml, risk-e2e.toml, tier-risk-e2e.toml, docker-compose.risk-override.yml
- `tests/e2e/render-report.sh` auto-append logic (fixes pre-existing nightly report gap)
- Documentation + spike findings
- Two real product contract gaps identified during verification

## The Brutal Truth

The stale binary trap cost debugging time we didn't need to spend. A prebuilt target/release/waf (2026-06-30) vs a 2026-07-06 risk-engine change silently disabled risk scoring—no error, no startup warning, no canary fire. The suite caught it, but that's a gap in the harness itself: a stale binary should fail loudly at boot or during gateway init, not silently eat risk signals. Forced a fresh `cargo build --release -p prx-waf` before docker image build.

The spike discovered the canary trap: /canary/trap pins score to 100 + bans the IP, which works for enabled/canary behavioral groups but breaks decay/credit/clear testing (can't observe decay when the score is pinned). Had to design around it.

Two product findings: the config API validates structure but not semantics (well-typed invalid backend persists as HTTP 200, relies on the engine's reload to backstop it), AND decay/ttl params are boot-only but emit NO warning when they no-op after reload. These aren't bugs in the test suite—they're real contract violations that slipped through code review.

## Technical Details

**Spike Discovery (Phase 1)**: Deterministic score-raise via X-Forwarded-For anomaly: private-after-public chain + chain length > 5 + duplicates → +10/request, decays over time. This eliminated the feared "need device-fp/ingest to drive risk" path and de-risked the whole plan.

**Stale Binary Silence**: MemoryRiskStore was never initialized (no risk reload on boot), so canary requests returned 200 OK with default-low scores. Adding a smoke gate to README: if run-risk-config.sh starts without a canary fire on first request, fail loudly with "binary is stale or risk-disabled."

**Product Gap #1 (Validation)**: PUT /api/risk/config with backend: "postgres" (invalid, not supported) returns HTTP 200, persists to config. Only the engine's reload validate() rejects it on next startup; no 400. Asserted as contract violation (must validate semantics at the API, not defer to engine).

**Product Gap #2 (Boot-Only Config)**: Decay params (decay_rate, min_clean_streak, max_decay) and ttl_secs/gc_interval_secs are captured at DecayConfig construction and store init. The config reload watcher swaps the config snapshot but never rebuilds MemoryRiskStore—so changes to these params silently no-op until restart. Unlike the backend validation gap, NO warning is logged. UI admin assumes these are live.

**Code Review Fixes**: H1 — ttl behavioral test was a phantom proof (PUT ttl:4 but measured at boot ttl:5); relabeled as "boot-config expiry observed" + folded into gap #2 finding. M2 — hardcoding risk-config in render-report's SUITES would MISSING/FAIL every nightly report (no nightly job); fixed by auto-appending present-but-unlisted suites (both fixes the risk config and pre-existing interop-not-rendered gap).

## What We Tried

1. Initial canary design (pin score to 100): worked for enabled/canary groups but broke decay/credit tests.
2. Pivot to X-Forwarded-For anomaly: successful; deterministic, no gear changes.
3. TTL test via PUT ttl:4 + wait: appeared to pass but was measuring boot config, not reload behavior. Honest relabel + gap doc'd.
4. Hardcoded suites in render-report: broke nightly report assumption. Switched to auto-append present-but-unlisted (cleaner, fixes pre-existing bug).

## Root Cause Analysis

**Stale binary**: No harness-level check for binary freshness vs code age. The gateway's risk module gracefully no-ops when MemoryRiskStore isn't initialized (returns default scores, no errors). This is sensible fallback behavior, but it masks a real deployment problem.

**Product gaps**: Both passed code review because the tests didn't probe the boundary. Config API validation assumes the engine's reload will backstop invalid semantics (it does, but late—after a restart). TTL/decay being boot-only was probably intentional (immutable store lifecycle), but it's invisible in the UI and the API accepts writes that silently no-op. Not malicious, but a contract lie.

## Lessons Learned

1. **Stale binary is invisible**: Add a smoke gate to E2E suites that forces a recent binary + validates risk signals on first request. Document in README that `cargo build --release -p prx-waf` is mandatory before docker image build (not optional).

2. **Graceful degradation masks deployment bugs**: Risk module's silent no-op on missing MemoryRiskStore is good fallback behavior, but pair it with a startup WARNING if risk config exists but wasn't loaded. Same for boot-only params: log a warning if a reload receives changes to ttl/decay params that will be ignored.

3. **E2E can surface contract violations**: Two real product gaps (validation deferred + boot-only params no-op) that passed code review because the tests didn't exist. This suite proved its value before nightly coverage even existed.

4. **Auto-append logic beats hardcoding**: Render-report's hardcoded SUITES list was brittle and broke pre-existing interop. Auto-append (present-but-unlisted) is more maintainable and fixes lateral bugs.

## Next Steps

- **NOT COMMITTED yet** (user deferred). Stack running on 26880/26827.
- Product gaps must be triaged: decide whether to validate semantics at API, or log warnings on boot-only params. This is a product decision, not a test suite issue.
- Smoke gate for binary freshness: add to run-risk-config.sh or harness.
- Document the operational setup (distinct ports, bind mount as DIRECTORY not file, busybox helper for root-owned config reset).
- When product gaps are fixed, re-run suite to validate.

---

**Status**: DONE
**Summary**: E2E suite for risk config admin API delivered and green (35/35). Two real product contract violations surfaced by the verification: config API validates structure not semantics, and decay/ttl params are boot-only but silently no-op on reload (no warning). Suite proved its value before nightly coverage existed.
**Concerns**: Stale binary trap cost debugging time; needs harness-level smoke check. Product gaps require triage and fix before production. Not committed pending user decision.
