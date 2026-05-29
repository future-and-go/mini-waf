# Red-Team Review: WAF Control Interface Interop S2 Plan

**Reviewer:** code-reviewer | **Date:** 2026-05-29 | **Verdict:** APPROVE_WITH_CONDITIONS

## Executive Summary

Plan is well-structured with correct TDD approach, sound ArcSwap architecture, and solid test coverage. Found 3 critical, 4 high, and 5 medium findings. The most dangerous are: (1) stores unreachable from `WafEngine` for reset, (2) timing-attack bypass in constant-time comparison, (3) missing engine integration for per-feature mode resolution.

---

## Findings Table

| ID | Sev | Phase | Title | Fix |
|----|-----|-------|-------|-----|
| F1 | **CRIT** | P4 | Reset cannot reach `rl_store`, `ddos_rl_store`, `ddos_counter_store` | Stores are local vars in constructor, moved into checkers. Plan's `Check::reset_state()` approach is correct BUT plan also shows direct field access (`self.tx_velocity_store.clear_all()`) mixed with trait iteration. Unify: either store all resettable Arc refs as engine fields, or commit fully to `Check::reset_state()`. Currently neither path is complete. |
| F2 | **CRIT** | P2 | Constant-time comparison short-circuits on length | `benchmark_secret_guard` lines 217-218: `provided.len() != expected.len()` returns early before `constant_time_eq`. An attacker can binary-search the secret length in O(log n) requests. Fix: always run `constant_time_eq` with padding or use `subtle::ConstantTimeEq` which handles length internally. The plan's own `constant_time_eq` function (line 233) also early-returns on length mismatch. |
| F3 | **CRIT** | P1+Engine | No plan for engine `inspect()` to consult `ModeRegistry` | Engine has 11 hardcoded `ctx.host_config.log_only_mode` checks. Plan builds `ModeRegistry` but never describes how `inspect()` switches from per-host boolean to per-feature/policy mode resolution. Without this, `set_profile` has zero effect on traffic. Phase 7 tests assume this works (`mode_toggle_affects_engine_behavior`) but no phase implements it. |
| F4 | **HIGH** | P4 | Risk scorer store not accessible for reset | `Scorer<S: RiskStore>` holds the risk store but is not a field on `WafEngine`. Plan claims `risk_store.reset_all()` (which exists on the trait) but shows no path to reach it from `reset_runtime_state()`. Plan comment: "will need to expose risk_store or add reset to scorer" -- this is unresolved design. |
| F5 | **HIGH** | P4 | Behavior recorder and identity store live in gateway proxy, not engine | `BehaviorRecorder` and `DeviceFpDetector` (which holds `IdentityStore`) are fields on `gateway::proxy::WafProxy`, not `WafEngine`. Plan Phase 4 lists them under `WafEngine::reset_runtime_state()` but engine has no reference to them. Fix: add `behavior_recorder: Option<Arc<BehaviorRecorder>>` and `identity_store: Option<Arc<dyn IdentityStore>>` to `AppState`, or accept partial reset with documented gap. |
| F6 | **HIGH** | P4 | Partial reset not atomic -- contract requires atomicity | Contract S2.4 says "success response MUST NOT be returned until all temporary runtime state... has been fully cleared" and "MUST NOT expose partially reset state after success." Plan clears stores sequentially (engine -> cache -> crowdsec -> mode). A concurrent request between step 1 and step 4 sees partially reset state. Plan acknowledges this but defers to Phase 7 integration test -- insufficient mitigation. Consider: drain in-flight requests during reset, or at minimum set a "resetting" flag checked by `inspect()`. |
| F7 | **HIGH** | P5 | `set_all("enforce")` should clear overrides per contract, uses SHOULD language | Contract line 186: "Any previous feature-level or policy-level log_only overrides SHOULD be cleared." Plan implements `set_all()` as clearing all overrides (correct, plan line 208-209). However, the `applied` response for `scope: "all"` does not echo `features` or `policies` fields. Contract examples show `applied` echoing the request shape. Plan response: `{ "scope": "all", "mode": req.mode }` -- verify contract doesn't require additional fields. This is likely fine per contract minimal schema. |
| F8 | **MED** | P2 | Default secret hardcoded in code and tests | `"waf-hackathon-2026-ctrl"` is the contract-mandated secret, but `default_benchmark_secret()` returns it as the serde default. This means a production deployment without `[interop]` config section silently exposes control endpoints with a well-known secret. Fix: require `benchmark_secret` to be explicitly configured when `enabled = true`, or disable interop by default (`enabled: false`). |
| F9 | **MED** | P4 | `as_millis() as i64` truncation | Plan uses `.as_millis() as i64` for `ts_ms`. `Duration::as_millis()` returns `u128`; casting to `i64` silently truncates after year ~292 million. While safe in practice, this violates the "NO .unwrap()" spirit -- use `i64::try_from(...).unwrap_or(i64::MAX)` pattern already used elsewhere in the codebase (e.g., `ddos/check.rs:213`). |
| F10 | **MED** | P1 | `FeatureCatalog::all()` returns `HashMap` -- allocates on every call | Plan says "zero allocation on read path" but `all()` returns a new HashMap each call. Capabilities handler calls it per request. Fix: return `&'static HashMap` via `LazyLock` or `OnceLock`, or return `&'static [(&str, FeatureInfo)]` slice. |
| F11 | **MED** | P2 | Error response leaks detail about interop state | When `enabled = false`, response is `404 {"ok": false, "error": "interop disabled"}`. This reveals to an external attacker that interop module exists. Use bare `404 Not Found` with no JSON body to be indistinguishable from a missing route. |
| F12 | **MED** | P5 | Empty `features`/`policies` arrays not validated identically | Plan validates `Some(f) if !f.is_empty()` for features but the serde `#[serde(default)]` means missing field deserializes as `None`. JSON `{"scope":"features","mode":"log_only","features":[]}` would match `Some(f) if !f.is_empty()` as false (empty vec), returning 400 -- correct. But `{"scope":"features","mode":"log_only"}` would match `None`, also returning 400 -- correct. Edge case: `{"scope":"features","mode":"log_only","features":null}` -- with `Option<Vec<String>>` this deserializes as `None`, handled correctly. No actual bug, but worth a test. |

---

## Contract Compliance Matrix

| Contract Section | Requirement | Plan Coverage | Status |
|-----------------|-------------|---------------|--------|
| S2.1 | 4 endpoints at `/__waf_control/*` | All 4 defined in P2-P6 | PASS |
| S2.2 | `X-Benchmark-Secret` auth, 403 on missing/invalid | P2 middleware | PASS (with F2 caveat) |
| S2.3 | `GET /capabilities` returns features+active | P3 handler + tests | PASS |
| S2.3 | Feature/policy names stable within benchmark run | Static catalog | PASS |
| S2.4 | `POST /reset_state` clears all temp state | P4 lists 10 stores | PARTIAL (F1, F4, F5) |
| S2.4 | MUST NOT modify audit log | P4 response: `audit_log_preserved: true` | PASS |
| S2.4 | Synchronous + atomic reset | Sequential clear, not atomic | FAIL (F6) |
| S2.5 | `POST /set_profile` 3 scopes | P5 implements all 3 | PASS |
| S2.5 | Unsupported items in response | `unsupported[]` array | PASS |
| S2.5 | `scope: "all"` clears overrides | `set_all()` clears maps | PASS |
| S2.6 | `POST /flush_cache` | P6 reuses existing flush | PASS |
| S2.7 | `X-WAF-Mode` header on every response | **NOT IN PLAN SCOPE** | NOT ADDRESSED |

**S2.7 Gap:** Contract requires `X-WAF-Mode` header on every proxied response. Plan mentions parent plan Phase 2 handles this, but no cross-reference ensures `ModeRegistry` is wired to the header injection path. Should be explicit dependency.

---

## Security Assessment

1. **Timing attack (F2):** Length check before constant-time compare leaks secret length. Use `subtle::ConstantTimeEq` (already a dep) on fixed-length hashes, or pad shorter input.
2. **Default secret exposure (F8):** Well-known secret active by default when `[interop]` missing from config. Production risk: any attacker who reads the contract can reset WAF state.
3. **Error detail leak (F11):** 404 response body reveals interop module existence.
4. **Secret not logged:** Plan explicitly states this -- good.
5. **No admin-IP binding mentioned:** Contract says "local/admin-only." Plan relies solely on secret header, no IP allowlist. Consider reusing existing `security_config.admin_ip_allowlist` if available.

## Concurrency Assessment

1. **ArcSwap reads (ModeRegistry):** Correct. `arc_swap::ArcSwap` load is lock-free atomic. Readers see consistent snapshot. Multiple writers race on `rcu()` or explicit `store()` but ArcSwap handles this safely (last writer wins).
2. **Reset atomicity (F6):** Sequential store clears create a window where some stores are cleared and others are not. In-flight requests see inconsistent state. Contract scoring penalty risk.
3. **Write-write race on `set_features`:** If two concurrent `set_profile` requests modify different features, the second `store()` overwrites the first's changes. Plan should use `ArcSwap::rcu()` for read-copy-update pattern to merge concurrent writes. Currently plan shows `set_feature` but not the implementation -- ensure `rcu()` is used.
4. **Test concurrency (P1 line 155):** `h.join().unwrap()` in test code is acceptable (test-only context).

---

## Missing Tests

1. **No test for `X-Benchmark-Secret` with non-UTF8 header value** -- `to_str().ok()` returns None for non-ASCII, treated as empty string. Test this edge case.
2. **No test for very large request body on `set_profile`** -- thousands of feature names. Should test DoS resistance / body size limit.
3. **No test for concurrent `set_profile` write-write conflicts** -- Phase 7 concurrent test only tests read-write, not write-write.
4. **No test verifying reset preserves audit log file** -- contract explicitly requires this, test should assert file exists and has same content post-reset.
5. **No test for `reset_state` during active traffic** -- verify in-flight requests complete correctly.
6. **No negative test for `POST` on `/capabilities` or `GET` on `/reset_state`** -- method mismatch behavior.
7. **No test for `Content-Type: application/json` requirement on POST endpoints** -- what happens with form-encoded body?

---

## Iron Rule Violations in Pseudocode

| Rule | Location | Issue |
|------|----------|-------|
| NO `.unwrap()` in prod | P4 line 321: `.unwrap_or_default()` | PASS -- uses safe fallback |
| NO `.unwrap()` in prod | P2 line 215: `.unwrap_or("")` | PASS |
| NO dead code | P2 lines 242-253: stub handlers | Temporary stubs -- acceptable if replaced in later phases. Add `#[allow(dead_code)]` or remove stubs once real handlers land. |
| NO `std::sync::Mutex` | Not used anywhere | PASS |
| Minimize allocations | F10: `HashMap` alloc per capabilities request | FAIL -- use static catalog |
| Explicit error handling | P4 line 303: engine reset error handled, but cache/crowdsec errors silently succeed | PARTIAL -- `cache.flush().await` and `cc.clear_all()` have no error handling |

---

## Verdict: APPROVE_WITH_CONDITIONS

### Blocking Conditions (must fix before implementation):

1. **F2:** Replace hand-rolled constant-time comparison with `subtle::ConstantTimeEq` on fixed-size hashes (SHA-256 both sides), or at minimum run the XOR comparison on max(len_a, len_b) with zero-padding.
2. **F3:** Add an explicit implementation step (Phase 1.5 or Phase 5 addendum) describing how `engine.inspect()` will consult `ModeRegistry` instead of `host_config.log_only_mode`. Without this, `set_profile` is a no-op.
3. **F1 + F4 + F5:** Resolve the reset architecture: decide between (a) `Check::reset_state()` trait method on all checkers + new reset methods on proxy-layer components accessible from `AppState`, or (b) storing all resettable `Arc` refs as `WafEngine` fields. Document which stores are reset from engine vs. API layer.

### Non-blocking Recommendations:

- F6: Document the atomicity gap and plan a follow-up for drain-based reset.
- F8: Default `enabled: false` for production safety; require explicit opt-in.
- F9: Use `i64::try_from().unwrap_or(i64::MAX)` for consistency with codebase.
- F10: Use `LazyLock`/`OnceLock` for static catalog to avoid per-request allocation.
- F11: Return bare 404 when disabled, no JSON body.
- Add missing tests listed above, especially audit log preservation and write-write concurrency.

---

## Unresolved Questions

1. Where will `RiskScorer<S>` store reference be exposed for reset? Neither engine nor AppState currently holds it.
2. Should `reset_state` also clear the `request_counter` and `blocked_counter` atomics on AppState? These are runtime state visible to benchmarker via stats endpoints.
3. Contract S2.7 (`X-WAF-Mode` header) dependency -- is this tracked in parent plan with explicit blocker relationship?
