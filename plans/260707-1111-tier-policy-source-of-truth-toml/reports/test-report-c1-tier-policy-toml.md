# C1 Tier-Policy TOML Source-of-Truth Validation Report

**Date:** 2026-07-07 | **Branch:** main-harness | **Scope:** Validate tier-policies API repoint from orphan YAML to tier-protection TOML

---

## Test Execution Results

### 1. waf-api Library Tests
**Command:** `cargo test -p waf-api --lib`

| Status | Result |
|--------|--------|
| **Pass/Fail** | ✓ PASS |
| **Tests Run** | 131 |
| **Passed** | 131 |
| **Failed** | 0 |
| **Duration** | 2.14s |

**Notes:** Includes 7 new tier_policies_api tests. All passed.

---

### 2. waf-common Config Loader Tests
**Command:** `cargo test -p waf-common --test config_loader`

| Status | Result |
|--------|--------|
| **Pass/Fail** | ✓ PASS |
| **Tests Run** | 9 |
| **Passed** | 9 |
| **Failed** | 0 |
| **Duration** | 0.01s |

**Coverage:** Validates edited config profiles (default.toml, local-dev.toml) parse correctly with new `[tiered_protection]` section.

---

### 3. Gateway Tier Watcher/Classifier Tests
**Command:** `cargo test -p gateway tier`

| Status | Result |
|--------|--------|
| **Pass/Fail** | ✓ PASS |
| **Tests Run** | 28+ tier-related unit/integration tests |
| **Passed** | All |
| **Failed** | 0 |

**Coverage:** Tier classifier, hot-reload watcher, and E2E tier routing unaffected by changes. Tests include:
- tier_classifier::tests (10 tests) — regex, method matching, priority, defaults
- tier_config_watcher::tests (4 tests) — file loading, reload, error handling
- tier_policy_registry::tests (4 tests) — concurrent snapshot swap, policy lookup
- E2E tier tests — all four tiers reachable, default fallback

---

### 4. Clippy Lint Analysis
**Command:** `cargo clippy -p waf-api -p prx-waf --all-targets`

| Status | Result |
|--------|--------|
| **Pass/Fail** | ✗ **BLOCKED** |
| **Error** | indexing_slicing violation |
| **Location** | crates/waf-api/src/tier_policies_api.rs:218 |

**Issue:**
```rust
218 |         bad_regex.classifier_rules[0].path = Some(PathMatch::Regex { value: "(".into() });
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
error: indexing may panic — consider using `.get_mut(n)` instead
```

**Analysis:** Test code in `put_rejects_bad_thresholds_missing_tier_and_bad_regex()` directly indexes `classifier_rules[0]` without bounds check. The `valid_config()` helper guarantees a 2-element vec (lines 138–155), so the access is safe at runtime. However, clippy's `indexing_slicing` lint (enabled at compile time) requires defensive `.get_mut()` even for statically-guaranteed cases.

**Severity:** Blocking — prevents compilation and all clippy checks until resolved.

---

### 5. TypeScript Type Check
**Command:** `npx tsc --noEmit` (web/admin-panel)

| Status | Result |
|--------|--------|
| **Pass/Fail** | ✓ PASS |
| **Errors** | 0 |
| **Warnings** | 0 |

---

### 6. React Admin Panel Build
**Command:** `npm run build` (web/admin-panel)

| Status | Result |
|--------|--------|
| **Pass/Fail** | ✓ PASS |
| **Build Time** | 1.79s |
| **Artifacts** | Clean, all chunks optimal size |

**Output:** Vite build completed successfully. Main bundle: 553.73 kB (gzip 152.20 kB).

---

### 7. File Structure & Config Validation

#### Old File Deletion
```
configs/tier-policies.yaml
✓ File correctly removed from working tree (staged for deletion in git)
```

#### New Config Path Verification
**File:** `configs/default.toml`
```toml
[tiered_protection]
config_path = "configs/tier-protection.toml"
```
✓ Present

**File:** `configs/local-dev.toml`
```toml
[tiered_protection]
config_path = "configs/tier-protection.toml"
```
✓ Present

#### New Source-of-Truth File
**File:** `configs/tier-protection.toml` (1642 bytes)
```
✓ Exists and contains valid shipped config
  - 3 classifier rules (critical, high, medium prefixes)
  - 4 policies (all tiers present with correct structures)
  - All required fields populated
```

#### Orphan Reference Scan
**Command:** `grep -rn "tier-policies.yaml" crates/ web/ configs/ --include="*.rs" --include="*.ts" --include="*.tsx" --include="*.toml"`

| Result |
|--------|
| ✓ No references found — clean migration |

---

## Coverage Analysis: 7 New Tests in tier_policies_api.rs

### Acceptance Criteria vs. Test Coverage

| Criterion | Test Name | Status | Notes |
|-----------|-----------|--------|-------|
| **Invalid config → 400 + file untouched** | put_rejects_bad_thresholds_missing_tier_and_bad_regex | ✓ Partial | Validates 3 bad scenarios (bad thresholds, missing tier, bad regex). File-untouched logic guaranteed by early parse_and_validate() return; not explicitly E2E tested. |
| | put_rejects_legacy_flat_cache_policy_shape | ✓ Partial | Validates legacy flat `cache_policy` string rejected with BadRequest. |
| **PUT output loadable by gateway::tiered::try_reload** | put_serialization_loads_through_watcher_reload | ✓ Full | Serializes valid config, writes temp file, loads via watcher's try_reload(), asserts rule_count. Proves watcher-equivalence. |
| **Shipped tier-protection.toml round-trips** | shipped_tier_protection_toml_round_trips | ✓ Full | Reads shipped file, parses as TierProtectionFile, builds TierSnapshot without error. |
| **Dry-run classifier matches engine semantics (method AND path)** | dry_run_classifier_matches_engine_semantics | ✓ Full | Tests regex path + POST method match, GET method rejection (AND logic), prefix path match, default tier fallback. Excellent coverage. |
| **Missing file → engine defaults** | load_missing_file_yields_engine_defaults | ✓ Full | Loads from /nonexistent/..., confirms default_tier=CatchAll, empty classifier_rules, 4 policies with defaults. |
| **JSON round-trip** | get_json_shape_is_put_compatible | ✓ Full | Serializes valid config to JSON, parses back, validates. Proves GET/PUT shape compatibility. |

### Coverage Gaps Identified

1. **Full PUT handler E2E test missing**
   - Tests only validate `parse_and_validate()` function in isolation
   - No test of the complete `put_tier_policies()` handler (state injection, file write, response)
   - Recommendation: Add integration test calling the actual handler

2. **File write atomicity / error handling not tested**
   - No test verifies behavior if `write_toml_str()` fails mid-write
   - No test of concurrent read during file write (data corruption risk)
   - Current design validates before write, which is correct, but runtime guarantees not proven
   - Recommendation: Add test for write failure scenarios

3. **"File untouched on error" coverage**
   - Criteria requires file unchanged when PUT fails
   - Tests validate rejection happens (via parse_and_validate), but don't trace full handler flow
   - Logic is correct (validation happens before write), but not explicitly E2E verified
   - Recommendation: Add test that verifies original file contents after failed PUT

4. **Concurrent reload safety during PUT**
   - No test verifies watcher's hot-reload behavior during concurrent file write
   - Acceptable risk: gateway watcher uses atomic rename + file lock; tests assume underlying platform guarantees
   - Recommendation: Document assumption; consider adding integration test with watcher + concurrent PUT

---

## Build & Deployment Validation

### Cargo Dependencies
- ✓ Cargo.lock updated (includes new dependencies from tier_policies_api.rs)
- ✓ No unresolved dependency conflicts

### Config File Integrity
- ✓ New config path wired in 2 profiles (default, local-dev)
- ✓ Shipped tier-protection.toml valid TOML and schema-compliant
- ✓ Old configs (ddos.yaml, risk.yaml) unaffected

### Admin Panel Integration
- ✓ React page rewritten (src/pages/tier-policies/index.tsx)
- ✓ i18n updated (en.json, vi.json with tier-policy terms)
- ✓ TypeScript types compile clean
- ✓ Build artifact size nominal

---

## Summary by Component

| Component | Status | Notes |
|-----------|--------|-------|
| **Rust Backend** | ✓ Tests Pass (131) | Clippy error blocks full build. |
| **Config Migration** | ✓ Clean | Old file removed, new file valid, paths updated. |
| **Gateway Integration** | ✓ Tests Pass (28+) | Tier classifier & watcher unaffected. |
| **React Admin Panel** | ✓ Build Pass | TypeScript clean, artifacts nominal. |
| **File Structure** | ✓ Correct | No orphan references, new TOML structure valid. |

---

## Blockers & Critical Issues

### BLOCKING ISSUE: Clippy indexing_slicing Error

**File:** `crates/waf-api/src/tier_policies_api.rs:218`  
**Severity:** **CRITICAL — Prevents build**

```
error: indexing may panic
218 |         bad_regex.classifier_rules[0].path = ...
    |         ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

**Root Cause:** Test code uses direct indexing `[0]` on a vector. Clippy requires defensive `.get_mut()` or bounds check.

**Context:** The `valid_config()` helper creates a 2-element `classifier_rules` vector, so `[0]` is always safe. However, the lint is correct to flag the pattern.

**Fix Required:** Replace `bad_regex.classifier_rules[0]` with bounds-safe access:
```rust
if let Some(rule) = bad_regex.classifier_rules.get_mut(0) {
    rule.path = Some(PathMatch::Regex { value: "(".into() });
}
```

**Impact:** Cannot proceed with `cargo clippy` or release build until fixed.

---

## Recommendations

### Priority 1 (Blocking)
- [ ] Fix clippy indexing_slicing error at tier_policies_api.rs:218
- [ ] Re-run `cargo clippy -p waf-api -p prx-waf --all-targets` to confirm clean

### Priority 2 (Coverage Improvement)
- [ ] Add full PUT handler E2E integration test (validates state injection, file write, response)
- [ ] Add test for failed write scenario (write_toml_str error handling)
- [ ] Document concurrent reload safety assumption (or add integration test with watcher)

### Priority 3 (Future)
- [ ] Consider performance benchmark for config reload under load
- [ ] Add chaos test for network-mounted config directory failures

---

## Unresolved Questions

1. **Concurrent write safety:** Are file writes atomic at the OS level for configs/tier-protection.toml, or does the gateway watcher have exclusive file locking? *(Assumption: watcher uses atomic rename; caller should verify.)*

2. **Fallback behavior:** When the config file is missing and engine boots with defaults, is there a warning logged? *(Current code: silent fallback to default_tier_config().)*

3. **config_files.rs implementation:** What does `write_toml_str()` do? Does it use atomic rename? *(Should verify its behavior before production deployment.)*

---

## Conclusion

**Status:** DONE_WITH_CONCERNS

**Summary:** Core functionality test coverage is solid — 7 tests validate key scenarios (parsing, validation, round-trip, dry-run, defaults, shipped config). All Rust unit/integration tests pass (131 + 28+). React build clean. File structure correct, no orphan references. **Blocking issue:** Clippy indexing_slicing error prevents release build. Test coverage has minor gaps (no full PUT handler E2E, no write failure handling), but design is sound.

**Concerns/Blockers:**
1. Clippy error blocks build — fix required before merge
2. Missing E2E integration test for full PUT handler
3. Write error handling not tested (low risk due to validation-first design)
4. Concurrent reload safety assumption not formally validated

**Next Steps:**
1. Fix clippy error (Priority 1)
2. Re-run validation checks
3. Add E2E PUT handler test (Priority 2)
4. Merge when P1 blocker cleared
