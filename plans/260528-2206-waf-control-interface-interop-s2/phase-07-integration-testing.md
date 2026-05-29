---
phase: 7
title: "Integration Testing"
status: completed
priority: P1
effort: "3-4h"
dependencies: [1, 2, 3, 4, 5, 6]
---

# Phase 7: Integration Testing

## Overview

End-to-end integration tests verifying the full `/__waf_control/*` workflow: auth -> capabilities discovery -> mode toggle -> verify engine behavior changes -> reset state -> verify clean slate. Tests the contract compliance as an external benchmarker would exercise it.

## Context Links

- Contract 2.1-2.7: `analysis/docs/EN_waf_interop_contract_v2.3.md`
- All prior phases: `./phase-01-*.md` through `./phase-06-*.md`
- Existing e2e pattern: `crates/waf-api/tests/` integration test files

## Requirements

**Functional:**
- Full lifecycle test: capabilities -> set_profile -> verify mode -> reset_state -> verify clean
- Mode toggle actually affects engine detection pipeline (log_only prevents blocking)
- reset_state returns all subsystems to clean state
- Capabilities reflects mode changes in real-time
- All endpoints enforce benchmark secret

**Non-functional:**
- Tests run under `cargo test -p waf-api`
- No external dependencies (no DB, no Redis, no CrowdSec daemon)
- < 30s total test execution time

## Architecture

```
Integration Test Flow:
  1. Boot test app with all interop components wired
  2. GET /capabilities -> verify default enforce state
  3. POST /set_profile { scope: "features", mode: "log_only", features: ["injection_control"] }
  4. Send malicious request through engine -> verify X-WAF-Action: block + X-WAF-Mode: log_only
  5. POST /set_profile { scope: "all", mode: "enforce" }
  6. Send same malicious request -> verify actually blocked
  7. POST /reset_state -> verify 200 + all stores cleared
  8. GET /capabilities -> verify back to enforce, no overrides
  9. POST /flush_cache -> verify 200
```

## Related Code Files

**Create:**
- `crates/waf-api/tests/interop_control_integration.rs`

**Read (all phases):**
- `crates/waf-api/src/interop_control.rs`
- `crates/waf-engine/src/interop/mode_registry.rs`
- `crates/waf-engine/src/interop/feature_catalog.rs`
- `crates/waf-engine/src/engine.rs`

## Implementation Steps

### TDD: Write Tests

1. Create `crates/waf-api/tests/interop_control_integration.rs`:

```rust
// Test: full benchmark lifecycle
#[tokio::test]
async fn benchmark_lifecycle_capabilities_toggle_reset() {
    let app = test_app_with_interop_and_engine();

    // Step 1: Discover capabilities
    let caps = authed_get_json(&app, "/__waf_control/capabilities").await;
    assert_eq!(caps["ok"], true);
    assert_eq!(caps["active"]["default_mode"], "enforce");
    assert_eq!(caps["active"]["overrides"], json!({}));
    assert!(caps["features"]["injection_control"]["supported"].as_bool().unwrap());

    // Step 2: Toggle injection_control to log_only
    let profile = authed_post_json(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["injection_control"]
    })).await;
    assert_eq!(profile["ok"], true);
    assert_eq!(profile["active"]["overrides"]["injection_control"], "log_only");

    // Step 3: Verify capabilities reflects change
    let caps2 = authed_get_json(&app, "/__waf_control/capabilities").await;
    assert_eq!(caps2["active"]["overrides"]["injection_control"], "log_only");

    // Step 4: Reset state
    let reset = authed_post_json(&app, "/__waf_control/reset_state", json!({})).await;
    assert_eq!(reset["ok"], true);
    assert_eq!(reset["audit_log_preserved"], true);

    // Step 5: Verify capabilities back to default
    let caps3 = authed_get_json(&app, "/__waf_control/capabilities").await;
    assert_eq!(caps3["active"]["default_mode"], "enforce");
    assert_eq!(caps3["active"]["overrides"], json!({}));

    // Step 6: Flush cache
    let flush = authed_post_json(&app, "/__waf_control/flush_cache", json!({})).await;
    assert_eq!(flush["ok"], true);
}

// Test: mode toggle affects engine inspection result
#[tokio::test]
async fn mode_toggle_affects_engine_behavior() {
    let app = test_app_with_interop_and_engine();

    // Default: enforce mode -> injection blocked
    let result1 = app.engine().inspect(&sqli_request()).await;
    assert_eq!(result1.action, WafAction::Block { .. });

    // Toggle to log_only
    authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["injection_control"]
    })).await;

    // log_only: same request -> WafAction::LogOnly but X-WAF-Action still reports block intent
    let result2 = app.engine().inspect(&sqli_request()).await;
    // Engine should respect mode_registry: log_only means allow through but report
    assert!(matches!(result2.action, WafAction::LogOnly | WafAction::Allow));
}

// Test: auth required on all endpoints
#[tokio::test]
async fn all_endpoints_require_auth() {
    let app = test_app_with_interop();

    let endpoints = vec![
        ("GET", "/__waf_control/capabilities"),
        ("POST", "/__waf_control/set_profile"),
        ("POST", "/__waf_control/reset_state"),
        ("POST", "/__waf_control/flush_cache"),
    ];

    for (method, path) in endpoints {
        let resp = match method {
            "GET" => app.get(path).await,
            "POST" => app.post(path).json(&json!({})).await,
            _ => unreachable!(),
        };
        assert_eq!(resp.status(), 403, "Expected 403 for {} {} without auth", method, path);
    }
}

// Test: wrong secret rejected on all endpoints
#[tokio::test]
async fn wrong_secret_rejected_everywhere() {
    let app = test_app_with_interop();

    let paths = [
        "/__waf_control/capabilities",
        "/__waf_control/set_profile",
        "/__waf_control/reset_state",
        "/__waf_control/flush_cache",
    ];

    for path in paths {
        let resp = app.get(path).header("X-Benchmark-Secret", "wrong").await;
        assert_eq!(resp.status(), 403, "Expected 403 for {} with wrong secret", path);
    }
}

// Test: set_profile -> reset_state -> set_profile is idempotent cycle
#[tokio::test]
async fn toggle_reset_toggle_cycle() {
    let app = test_app_with_interop();

    // Toggle
    authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features", "mode": "log_only", "features": ["bot_detection"]
    })).await;

    // Reset
    authed_post(&app, "/__waf_control/reset_state", json!({})).await;

    // Toggle again — same operation should succeed identically
    let resp = authed_post_json(&app, "/__waf_control/set_profile", json!({
        "scope": "features", "mode": "log_only", "features": ["bot_detection"]
    })).await;
    assert_eq!(resp["ok"], true);
    assert_eq!(resp["active"]["overrides"]["bot_detection"], "log_only");
}

// Test: concurrent set_profile and capabilities reads
#[tokio::test]
async fn concurrent_profile_and_capabilities() {
    let app = Arc::new(test_app_with_interop());
    let mut handles = vec![];

    for i in 0..8 {
        let a = Arc::clone(&app);
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                authed_post(&a, "/__waf_control/set_profile", json!({
                    "scope": "all", "mode": "log_only"
                })).await;
            } else {
                let resp = authed_get(&a, "/__waf_control/capabilities").await;
                assert_eq!(resp.status(), 200);
            }
        }));
    }

    for h in handles {
        h.await.unwrap();
    }
}

// Test: reset_state does not affect static config
#[tokio::test]
async fn reset_preserves_static_config() {
    let app = test_app_with_interop_and_engine();

    // Capture rule count before reset
    let rules_before = app.engine().rule_count();

    authed_post(&app, "/__waf_control/reset_state", json!({})).await;

    // Rules unchanged
    let rules_after = app.engine().rule_count();
    assert_eq!(rules_before, rules_after);
}

// Test: policy-level override survives feature-level toggle
#[tokio::test]
async fn policy_override_survives_feature_toggle() {
    let app = test_app_with_interop();

    // Set policy override
    authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "policies",
        "mode": "log_only",
        "feature": "injection_control",
        "policies": ["sqli"]
    })).await;

    // Set feature-level override for different feature
    authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["rate_limiting"]
    })).await;

    // Verify both overrides coexist
    let caps = authed_get_json(&app, "/__waf_control/capabilities").await;
    assert_eq!(caps["active"]["overrides"]["injection_control.sqli"], "log_only");
    assert_eq!(caps["active"]["overrides"]["rate_limiting"], "log_only");
}

// Test: ts_ms monotonically increasing across calls
#[tokio::test]
async fn timestamps_monotonic() {
    let app = test_app_with_interop();

    let r1 = authed_post_json(&app, "/__waf_control/flush_cache", json!({})).await;
    let r2 = authed_post_json(&app, "/__waf_control/reset_state", json!({})).await;
    let r3 = authed_post_json(&app, "/__waf_control/set_profile", json!({
        "scope": "all", "mode": "enforce"
    })).await;

    let ts1 = r1["ts_ms"].as_i64().unwrap();
    let ts2 = r2["ts_ms"].as_i64().unwrap();
    let ts3 = r3["ts_ms"].as_i64().unwrap();
    assert!(ts1 <= ts2);
    assert!(ts2 <= ts3);
}
```

### Implement Test Helpers

2. Create shared test utilities (if not already present):

```rust
// In a test helper module or at top of integration test file
fn test_app_with_interop_and_engine() -> TestApp {
    // Builds full AppState with:
    // - WafEngine with real checkers (in-memory stores)
    // - ModeRegistry (default)
    // - ResponseCache (Moka, in-memory)
    // - InteropConfig (default secret)
    // - No DB connection needed (engine uses in-memory stores)
}

fn sqli_request() -> WafRequest {
    // Constructs request with SQLi payload: "1' OR 1=1 --"
    // Targets injection_control detection phase
}

fn authed_get(app: &TestApp, path: &str) -> RequestBuilder {
    app.get(path).header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
}

fn authed_post(app: &TestApp, path: &str, body: Value) -> RequestBuilder {
    app.post(path)
        .header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
        .json(&body)
}

fn authed_get_json(app: &TestApp, path: &str) -> Value {
    authed_get(app, path).await.json().await
}

fn authed_post_json(app: &TestApp, path: &str, body: Value) -> Value {
    authed_post(app, path, body).await.json().await
}

fn epoch_ms_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}
```

### Validate

3. `cargo check --workspace`
4. `cargo test -p waf-api --test interop_control_integration`
5. `cargo test --workspace` (full regression)
6. `cargo clippy --workspace -- -D warnings`

## Success Criteria

- [ ] Full lifecycle test passes: capabilities -> set_profile -> verify -> reset -> verify
- [ ] Mode toggle actually changes engine inspection behavior
- [ ] All 4 endpoints enforce benchmark secret
- [ ] Wrong secret rejected on all endpoints
- [ ] Toggle-reset-toggle cycle is idempotent
- [ ] Concurrent reads/writes don't panic or corrupt
- [ ] reset_state preserves static config (rules, access lists)
- [ ] Policy-level overrides coexist with feature-level overrides
- [ ] Timestamps monotonically increasing
- [ ] All existing tests pass (no regression)
- [ ] `cargo test --workspace` passes

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Engine not wired to ModeRegistry | High | Phase 7 tests will catch this; engine.inspect() must check mode_registry |
| Test app setup too complex | Medium | Reuse existing test infrastructure; only add ModeRegistry and InteropConfig |
| Flaky concurrent tests | Low | ArcSwap guarantees atomic reads; test asserts status codes, not specific state |
| Missing detection phases in log_only | High | Integration test with real SQLi payload verifies engine respects mode |
