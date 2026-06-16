# E17 Challenge Lifecycle Contract - Test Validation Report

**Date:** 2026-06-16 13:31  
**Scope:** `cargo test -p waf-engine -p gateway`  
**Branch:** main-harness (uncommitted changes)

---

## Test Results Overview

**Total Tests Run:** 1,817  
**Passed:** 1,816  
**Failed:** 1  
**Skipped:** 0  
**Execution Time:** ~5-15s per crate

### Pass Breakdown by Suite

| Test Suite | Count | Pass | Fail |
|-----------|-------|------|------|
| `gateway` lib | 353 | 353 | — |
| `cache_backend_types` integration | 4 | 4 | — |
| `access_hot_reload` integration | 2 | 2 | — |
| `access_reload_under_load` integration | 1 | 1 | — |
| `access_reload_watcher_extras` integration | 4 | 4 | — |
| `audit_file_sink_integration` | 5 | 5 | — |
| `behavior_acceptance` | 5 | 5 | — |
| `behavior_property` | 3 | 3 | — |
| `challenge_config` | 16 | 16 | — |
| `challenge_flow` | 13 | 13 | — |
| `challenge_pow` | 20 | 20 | — |
| `challenge_renderer` | 12 | 11 | **1** |
| `waf-engine` lib | 1,380 | 1,380 | — |
| **TOTAL** | **1,817** | **1,816** | **1** |

---

## Failed Test Details

### Test: `render_challenge_page_contains_all_required_elements`

**Location:** `crates/waf-engine/tests/challenge_renderer.rs:30-42`  
**Crate:** waf-engine  
**Suite:** challenge_renderer integration tests

**Failure Output:**
```
thread 'render_challenge_page_contains_all_required_elements' panicked at 
crates/waf-engine/tests/challenge_renderer.rs:41:5:
cookie name missing

assertion failed: html.contains("__waf_cc=")
```

**Failing Assertion (line 41):**
```rust
assert!(html.contains("__waf_cc="), "cookie name missing");
```

**Root Cause Analysis:**

E17 implementation changed the challenge lifecycle from **client-side cookie** to **server-side cookie via POST handler**:

**Old Implementation (client-side, removed):**
```javascript
// From page_template.rs before E17
document.cookie="__waf_cc="+t+"."+n+";path=/;max-age=300;SameSite=Strict";
location.href=r
```

**New Implementation (server-side, E17):**
1. Page template JavaScript POSTs solve to `/challenge/verify`:
```javascript
fetch("/challenge/verify",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({challenge_token:t,nonce:""+n})})
```

2. Gateway handler `handle_challenge_verify()` (new in proxy_waf_response.rs) validates PoW and sets cookie:
```rust
pub async fn handle_challenge_verify(session: &mut Session, ctx: &GatewayCtx) -> pingora_core::Result<bool> {
    // ... verify JSON body ...
    if let Some(p) = solved {
        let mut resp = pingora_http::ResponseHeader::build(200, None)?;
        resp.insert_header(
            "set-cookie",
            format!("__waf_cc={}; Path=/; HttpOnly; SameSite=Lax", p.challenge_token),
        )?;
        // ...
    }
}
```

**Impact:** The test checks for `__waf_cc=` in the rendered HTML page, but the cookie is now set server-side via HTTP header in the `/challenge/verify` response. The cookie name never appears in the HTML page itself.

---

## Linting & Clippy Analysis

### Pre-existing Warnings (Known/Acceptable)

Per task guidance, the following pre-existing warnings in non-changed files are acceptable:

| File | Warning | Type |
|------|---------|------|
| `waf-common/src/config.rs:1091` | case-sensitive file extension comparison | warning (2 instances) |
| `waf-engine/src/logging/audit_file_sink.rs:74` | unnested or-patterns | warning |
| `waf-engine/src/engine.rs:470` | too many arguments (9/8) | warning |

### Clippy Errors in Test Code

**File:** `crates/waf-engine/src/logging/audit_file_sink.rs`  
**Lines:** 159, 182–184  
**Error Type:** `indexing_slicing` (panics possible)

```rust
159 |         assert_eq!(lines[0]["request_id"], "a");
    |                    ^^^^^^^^^^^^^^^^^^^^^^
    |
    = help: consider using `.get(n)` or `.get_mut(n)` instead

182 |         assert_eq!(lines[0]["seed"], true);
    |                    ^^^^^^^^^^^^^^^^
183 |         assert_eq!(lines[1]["n"], 1);
    |                    ^^^^^^^^^^^^^
184 |         assert_eq!(lines[2]["n"], 2);
    |                    ^^^^^^^^^^^^^
```

These are in test code (assertions, not production), and not in the changed files for E17. They are pre-existing.

### NEW Warnings in Changed Files

**Files inspected:**
- `crates/waf-engine/src/challenge/renderer.rs` (modified)
- `crates/waf-engine/src/challenge/page_template.rs` (modified)
- `crates/gateway/src/proxy_waf_response.rs` (modified)
- `crates/gateway/src/proxy.rs` (modified)

**Result:** ✅ **No NEW clippy warnings or errors in the four changed files above.**

Clippy output is clean for these files. The changes follow idiomatic Rust patterns:
- Token validation (renderer.rs): clear character set checks
- HTML escaping (page_template.rs): safe string building
- JSON deserialization (proxy_waf_response.rs): proper error handling
- Body reading (proxy_waf_response.rs): capped at 4 KiB with boundary checks

---

## Coverage & Code Quality Observations

### New Test Coverage Added in E17

**challenge_renderer.rs:**
- ✅ `accepts_real_issuer_token_with_dot` — verifies dot support in token charset

**page_template.rs (unit tests):**
- ✅ `contains_format_b_form` — verifies POST form structure
- ✅ `js_posts_to_verify_endpoint` — verifies fetch() to /challenge/verify
- ✅ `contains_challenge_literal` — Contract §4 detection (body contains "challenge")

**proxy_waf_response.rs (new):**
- New `handle_challenge_verify()` function is untested in the visible test suite
- Appears to have no corresponding integration test yet

### Coverage Gaps Identified

1. **`handle_challenge_verify()` has no visible test coverage.** The function:
   - Reads and caps request body (4 KiB)
   - Deserializes JSON (`VerifyRequest`)
   - Validates token charset
   - Verifies PoW (16-bit difficulty)
   - Sets `__waf_cc` cookie on success
   - Returns 403 on failure
   
   No test exercising success and failure paths found.

2. **`is_safe_token()` validation has no direct test coverage** (though indirectly exercised via handler).

3. **`read_verify_body()` cap enforcement** not explicitly tested.

---

## Performance Notes

- **PoW Test Execution:** 16-bit brute-force nonce search completes in <1ms per test (verified in challenge_pow suite)
- **Total Test Suite Time:** ~5–15 seconds (waf-engine compilation ~1m 05s first run, test execution ~2.1s)
- **No slow tests identified:** All tests complete in expected timeframes

---

## Build Status

✅ **Compilation Success**

```
Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 05s
```

All crates compile without errors.

---

## Critical Issues

### Issue 1: Failing Integration Test (BLOCKING)

**Severity:** HIGH — Test failure must be resolved before merge.

**Test:** `render_challenge_page_contains_all_required_elements`  
**Cause:** Test expectation (`__waf_cc=` in page HTML) no longer valid; cookie now server-side

**Required Fix:**
Update `crates/waf-engine/tests/challenge_renderer.rs:41` to reflect new server-side flow. The test should be removed or rewritten to verify:
- The page contains the form (✅ already covered by `contains_format_b_form`)
- The page contains the fetch() call (✅ already covered by `js_posts_to_verify_endpoint`)
- The page does NOT attempt to set the cookie client-side (implied by fetch behavior)

Alternatively, create a new integration test in gateway that verifies `handle_challenge_verify()` response sets the `__waf_cc` header.

### Issue 2: Missing Handler Test Coverage (HIGH)

**Function:** `handle_challenge_verify()`  
**Concern:** Server-side PoW verification and cookie minting has no direct test coverage.

**Recommended Tests:**
1. Valid PoW solve → 200 + `__waf_cc` cookie set
2. Invalid JSON → 403 (no cookie)
3. Invalid PoW → 403 (no cookie)
4. Unsafe token chars → 403 (no cookie)
5. Oversized body → error handling

---

## Recommendations

### Priority 1 (Before Merge)
1. **Fix failing test** `render_challenge_page_contains_all_required_elements`
   - Remove assertion for `__waf_cc=` in page HTML
   - OR move cookie verification to gateway integration test for `handle_challenge_verify()`

2. **Add test coverage for `handle_challenge_verify()`**
   - Success case: valid PoW + token → 200 + cookie
   - Failure case: invalid PoW → 403
   - Failure case: unsafe token → 403
   - Edge case: oversized body capping

### Priority 2 (Future Hardening)
1. Add fuzz tests for JSON deserialization in VerifyRequest
2. Add performance benchmark for PoW verification under load
3. Verify cookie lifetime and single-use enforcement (nonce consumption)

---

## Unresolved Questions

1. **Nonce Consumption:** Does the gateway verify that `__waf_cc` tokens are single-use? The code references "single-use-nonce check" in handle_challenge but shows only HMAC verification. Is nonce consumption tracked elsewhere?

2. **Test Coverage for Cookie-Based Bypass:** The old test `handle_challenge()` retry path (checking `__waf_cc` cookie on retried request) still exists. Does this path have adequate coverage after the handler change?

3. **Content-Negotiation in handle_challenge_verify():** The comments mention "content-negotiated challenge" in proxy_waf_response.rs. Is there JSON vs form handling logic, or is it always JSON from the fetch call?

---

## Summary

- **1,816 of 1,817 tests pass** (99.9% pass rate)
- **1 failing test** due to outdated expectation (cookie location change from client to server)
- **No new clippy warnings** in changed files
- **Recommended action:** Update test to match new server-side cookie implementation before merge

