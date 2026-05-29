---
phase: 3
title: "Capabilities Endpoint"
status: completed
priority: P1
effort: "3-4h"
dependencies: [1]
---

# Phase 3: Capabilities Endpoint

## Overview

Implement `GET /__waf_control/capabilities` — returns all WAF features, policies, toggle controls, and current active mode state. Benchmarker calls this first to discover what the WAF supports.

## Context Links

- Contract §2.3: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 55–95
- Compliance report §1.1: `plans/reports/researcher-260528-2206-waf-control-contract-compliance-analysis-report.md` §1.1
- Phase 1 (ModeRegistry): `./phase-01-moderegistry-core.md`

## Requirements

**Functional (contract §2.3):**
- Response must include `ok: true`
- `features` object maps feature names → `{ supported, toggleable, policies[] }`
- `active.default_mode` reflects current global default
- `active.overrides` maps all currently active feature/policy overrides
- Feature/policy names must be stable within a benchmark run
- Extra fields allowed but not required

**Non-functional:**
- Response must be valid JSON
- No pagination, no async — single synchronous response
- Should complete in < 1ms (pure in-memory reads)

## Architecture

```
GET /__waf_control/capabilities
  → benchmark_secret_guard (Phase 2)
  → capabilities_handler:
     1. Load FeatureCatalog::all() (static)
     2. Load ModeRegistry.snapshot() (ArcSwap)
     3. Build JSON response merging both
     4. Return 200 OK
```

## Related Code Files

**Modify:**
- `crates/waf-api/src/interop_control.rs` — replace stub `capabilities_handler`

**Read (dependencies from Phase 1):**
- `crates/waf-engine/src/interop/feature_catalog.rs`
- `crates/waf-engine/src/interop/mode_registry.rs`

## Implementation Steps

### TDD: Write Tests First

1. Add to `crates/waf-api/tests/interop_control_capabilities.rs`:

```rust
// Test: capabilities returns 200 with correct structure
#[tokio::test]
async fn capabilities_returns_ok() {
    let app = test_app_with_interop();
    let resp = authed_get(&app, "/__waf_control/capabilities").await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert!(body["features"].is_object());
    assert!(body["active"].is_object());
}

// Test: features contain required WAF capabilities
#[tokio::test]
async fn capabilities_has_core_features() {
    let app = test_app_with_interop();
    let body = authed_get_json(&app, "/__waf_control/capabilities").await;
    let features = &body["features"];
    assert!(features["access_control"].is_object());
    assert!(features["injection_control"].is_object());
    assert!(features["rate_limiting"].is_object());
    assert!(features["ddos_protection"].is_object());
    assert!(features["bot_detection"].is_object());
}

// Test: each feature has supported, toggleable, policies fields
#[tokio::test]
async fn capabilities_feature_structure() {
    let body = authed_get_json(&app, "/__waf_control/capabilities").await;
    let ac = &body["features"]["access_control"];
    assert_eq!(ac["supported"], true);
    assert_eq!(ac["toggleable"], true);
    assert!(ac["policies"].is_array());
    assert!(!ac["policies"].as_array().unwrap().is_empty());
}

// Test: active reflects default state on startup
#[tokio::test]
async fn capabilities_default_active_state() {
    let body = authed_get_json(&app, "/__waf_control/capabilities").await;
    assert_eq!(body["active"]["default_mode"], "enforce");
    assert_eq!(body["active"]["overrides"], json!({}));
}

// Test: active reflects overrides after set_profile
#[tokio::test]
async fn capabilities_reflects_mode_changes() {
    let app = test_app_with_interop();
    // Pre-set a mode override
    app.mode_registry().set_feature("injection_control", InteropMode::LogOnly);
    let body = authed_get_json(&app, "/__waf_control/capabilities").await;
    assert_eq!(body["active"]["overrides"]["injection_control"], "log_only");
}

// Test: policies listed match catalog
#[tokio::test]
async fn capabilities_policies_match_catalog() {
    let body = authed_get_json(&app, "/__waf_control/capabilities").await;
    let ic = &body["features"]["injection_control"];
    let policies: Vec<String> = ic["policies"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(policies.contains(&"sqli".to_string()));
    assert!(policies.contains(&"xss".to_string()));
    assert!(policies.contains(&"rce".to_string()));
}
```

### Implement

2. Replace `capabilities_handler` stub in `crates/waf-api/src/interop_control.rs`:

```rust
async fn capabilities_handler(
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    let catalog = FeatureCatalog::all();
    let mode_snap = state.mode_registry.snapshot();

    let mut features = serde_json::Map::new();
    for (name, info) in &catalog {
        features.insert(name.to_string(), json!({
            "supported": info.supported,
            "toggleable": info.toggleable,
            "policies": info.policies,
        }));
    }

    let mut overrides = serde_json::Map::new();
    for (k, v) in &mode_snap.feature_overrides {
        overrides.insert(k.clone(), json!(v.as_contract_str()));
    }
    for (k, v) in &mode_snap.policy_overrides {
        overrides.insert(k.clone(), json!(v.as_contract_str()));
    }

    Json(json!({
        "ok": true,
        "features": features,
        "active": {
            "default_mode": mode_snap.default_mode.as_contract_str(),
            "overrides": overrides,
        }
    }))
}
```

3. Add `mode_registry: Arc<ModeRegistry>` to `AppState`.

### Validate

4. `cargo check --workspace`
5. `cargo test -p waf-api --test interop_control_capabilities`
6. Manual: `curl -H "X-Benchmark-Secret: waf-hackathon-2026-ctrl" localhost:9527/__waf_control/capabilities | jq .`

## Success Criteria

- [ ] Returns `200 OK` with `ok: true`
- [ ] `features` object contains all 17 mapped features
- [ ] Each feature has `supported`, `toggleable`, `policies[]`
- [ ] `active.default_mode` is `"enforce"` on startup
- [ ] `active.overrides` is `{}` on startup
- [ ] After `set_feature("x", LogOnly)`, capabilities shows override
- [ ] JSON schema matches contract exactly
- [ ] `cargo check --workspace` passes

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Response schema mismatch | High | Test validates exact JSON structure against contract |
| Feature names unstable | Medium | Static catalog; names are `&'static str` |
