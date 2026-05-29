---
phase: 6
title: "Integration Testing & Regression"
status: pending
priority: P1
effort: "1d"
dependencies: [1, 2, 3, 4, 5]
---

# Phase 6: Integration Testing & Regression

## Overview

End-to-end validation that all 6 CRITICAL contract gaps are closed, existing functionality is preserved, and the full benchmarker workflow (startup → discovery → test runs → reset → re-test) works.

## Context Links

- Contract §7 (normalization matrix): `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 468–499
- Contract §8 (startup): same file lines 504–528
- Existing e2e: `tests/e2e-cluster.sh`
- Existing engine tests: `crates/waf-engine/tests/`
- Existing gateway tests: `crates/gateway/tests/`

## Requirements

**Functional:**
- Full benchmarker lifecycle: `./waf run` → health check → capabilities → test requests → reset → re-test
- All 6 `X-WAF-*` headers present on every response type
- JSONL audit log matches response headers (request_id correlation)
- Control interface works: toggle modes, verify behavior change
- Existing detection accuracy unchanged

**Non-functional:**
- All existing tests pass (zero regressions)
- New e2e test script runnable in CI
- `cargo clippy --workspace -- -D warnings` clean
- `cargo fmt --all -- --check` clean

## Architecture

### E2E Test Script: `tests/e2e-interop-contract-v23.sh`

Bash script that exercises the full contract lifecycle against a running WAF instance. Structured as sequential test cases with assertions.

```
Test Flow:
1. Build + start ./waf run (background)
2. Wait for health check
3. GET /__waf_control/capabilities → validate schema
4. Send clean request → verify X-WAF-Action: allow
5. Send SQLi payload → verify X-WAF-Action: block
6. Send flood → verify X-WAF-Action: rate_limit
7. Toggle attack_detection to log_only
8. Send SQLi again → verify X-WAF-Action: block + X-WAF-Mode: log_only + request reaches upstream
9. POST /__waf_control/reset_state → verify audit log preserved
10. POST /__waf_control/flush_cache → verify success
11. Read ./waf_audit.log → validate JSONL schema, field correctness, request_id correlation
12. Shutdown
```

### Regression Test Matrix

| Area | Test | Phase Validated |
|------|------|-----------------|
| WafAction serde | Existing + new variants round-trip | Phase 1 |
| Engine log_only | Intended action preserved | Phase 1 |
| Rate-limit action | Produces RateLimit not Block | Phase 1 |
| Response headers | All 6 headers on allow/block/challenge | Phase 2 |
| Header protection | Blocklist filter skips X-WAF-* | Phase 2 |
| JSONL audit | File format, field types, IP semantics | Phase 3 |
| VictoriaLogs primary | VictoriaLogs (primary) still receives events unchanged | Phase 3 |
| Control auth | Missing secret → 403 | Phase 4 |
| Capabilities | Correct feature/policy listing | Phase 4 |
| Mode toggle | set_profile changes engine behavior | Phase 4 |
| Reset state | Clears counters, preserves audit log | Phase 4 |
| Binary startup | `./waf run` + health check | Phase 5 |
| Config discovery | Auto-finds waf.toml | Phase 5 |

## Related Code Files

**Create:**
- `tests/e2e-interop-contract-v23.sh` — end-to-end contract compliance script

**Modify:**
- None — this phase is read-only validation

## Implementation Steps

### Regression: Existing Tests

1. **Run full workspace test suite**:
   ```bash
   cargo test --workspace
   ```
   Verify zero failures, zero new warnings.

2. **Run clippy + fmt**:
   ```bash
   cargo clippy --workspace -- -D warnings
   cargo fmt --all -- --check
   ```

3. **Run existing e2e** (if applicable):
   ```bash
   ./tests/e2e-cluster.sh
   ```

### Contract Compliance E2E Script

4. **Write `tests/e2e-interop-contract-v23.sh`** with these test cases:

   **TC-01: Startup contract**
   - Build with `cargo build --release`
   - Copy binary: `cp target/release/prx-waf ./waf`
   - Create `waf.toml` symlink
   - `./waf run &` → poll `GET /health` until 200 (timeout 30s)
   - Assert: health returns `{"status":"ok"}`

   **TC-02: Capabilities discovery**
   - `GET /__waf_control/capabilities` with correct secret
   - Assert: `ok: true`
   - Assert: `features` object non-empty
   - Assert: each feature has `supported`, `toggleable`, `policies` fields
   - Assert: `active.default_mode == "enforce"`

   **TC-03: Auth guard**
   - `GET /__waf_control/capabilities` without secret → assert 403
   - `GET /__waf_control/capabilities` with wrong secret → assert 403

   **TC-04: Clean request — allow**
   - `GET /` → assert `X-WAF-Action: allow`
   - Assert: `X-WAF-Request-Id` is UUID format
   - Assert: `X-WAF-Risk-Score` is integer
   - Assert: `X-WAF-Rule-Id` is `none`
   - Assert: `X-WAF-Cache` is `MISS` or `BYPASS`
   - Assert: `X-WAF-Mode: enforce`

   **TC-05: SQLi attack — block**
   - `GET /?id=1' OR '1'='1` → assert HTTP 403
   - Assert: `X-WAF-Action: block`
   - Assert: `X-WAF-Mode: enforce`
   - Assert: `X-WAF-Rule-Id` is NOT `none`
   - Assert: `X-WAF-Risk-Score` > 0

   **TC-06: Log-only mode**
   - `POST /__waf_control/set_profile` → `{"scope":"features","mode":"log_only","features":["attack_detection"]}`
   - Assert: response `ok: true`, overrides include `attack_detection: log_only`
   - `GET /?id=1' OR '1'='1` → assert HTTP 200 (NOT blocked)
   - Assert: `X-WAF-Action: block` (intended action)
   - Assert: `X-WAF-Mode: log_only`
   - Restore: `POST set_profile` → `{"scope":"all","mode":"enforce"}`

   **TC-07: Reset state**
   - `POST /__waf_control/reset_state` with secret
   - Assert: `ok: true`, `audit_log_preserved: true`
   - Assert: `./waf_audit.log` file still exists and size >= pre-reset size

   **TC-08: Flush cache**
   - `POST /__waf_control/flush_cache` with secret
   - Assert: `ok: true`

   **TC-09: JSONL audit log validation**
   - Read `./waf_audit.log`
   - For each line: assert valid JSON
   - Assert required fields: `request_id`, `ts_ms`, `ip`, `method`, `path`, `action`, `risk_score`, `mode`
   - Assert `ts_ms` is integer (not string)
   - Assert `ip` matches `127.0.0.1` pattern (loopback in test)
   - Assert `action` is one of 6 contract values
   - Cross-correlate: pick a `request_id` from audit log → match with `X-WAF-Request-Id` from TC-05

   **TC-10: Header-audit correlation**
   - From TC-05, capture `X-WAF-Request-Id` value
   - Grep `waf_audit.log` for that request_id
   - Assert: audit entry `action` matches header `X-WAF-Action`
   - Assert: audit entry `mode` matches header `X-WAF-Mode`

5. **Make script CI-friendly**:
   - Exit code 0 on all pass, non-zero on any failure
   - Output JUnit XML or TAP format for CI integration
   - Cleanup: kill background WAF process on exit (trap)
   - Timeout per test case: 10s

### Validate

6. Run the e2e script locally against the WAF
7. Fix any failures found
8. Run full regression suite one final time
9. Verify CI pipeline passes

## Success Criteria

- [ ] `cargo test --workspace` — zero failures
- [ ] `cargo clippy --workspace -- -D warnings` — clean
- [ ] `cargo fmt --all -- --check` — clean
- [ ] E2E script TC-01 through TC-10 all pass
- [ ] Audit log JSONL validates with `jq` parser
- [ ] Header-audit correlation verified
- [ ] Log-only mode correctly reports intended action without enforcement
- [ ] Reset state preserves audit log
- [ ] No existing detection accuracy regression

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| E2E requires running upstream server | Medium | Use mock upstream or loopback; WAF can proxy to localhost:8080 test server |
| E2E flaky due to timing (rate-limit, DDoS) | Medium | Use deterministic thresholds; reset state before each timing-sensitive test |
| CI environment lacks PostgreSQL | High | E2E tests that need DB should use testcontainers or skip with clear message |
| Audit log file permissions in CI | Low | Script creates in CWD; CI runners have write access |
