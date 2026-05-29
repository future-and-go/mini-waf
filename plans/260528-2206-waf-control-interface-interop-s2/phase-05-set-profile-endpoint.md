---
phase: 5
title: "Set Profile Endpoint"
status: completed
priority: P1
effort: "4-6h"
dependencies: [1, 2]
---

# Phase 5: Set Profile Endpoint

## Overview

Implement `POST /__waf_control/set_profile` — toggles enforce/log_only mode at three scopes: `all` (global default + clear overrides), `features` (batch feature override), `policies` (batch policy override under one feature). Validates requested names against `FeatureCatalog`, reports unsupported items in a lenient 200 response.

## Context Links

- Contract 2.5: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 132-259
- ModeRegistry API: Phase 1 `./phase-01-moderegistry-core.md`
- Auth middleware: Phase 2 `./phase-02-benchmark-auth-middleware.md`
- Compliance report: `plans/reports/researcher-260528-2206-waf-control-contract-compliance-analysis-report.md`

## Requirements

**Functional (contract 2.5):**
- Three scope variants: `all`, `features`, `policies`
- Two mode values: `enforce`, `log_only`
- `scope: "all"` sets default mode and clears all overrides (contract line 186)
- `scope: "features"` sets listed features only; omitted features unchanged
- `scope: "policies"` sets listed policies under one `feature`; omitted policies unchanged
- Unsupported features/policies returned in `unsupported[]` array (lenient 200, not 400)
- Response includes `applied` (echo of request), `active` (current state snapshot), `unsupported[]`, `ts_ms`
- `ok: true` always (even if some unsupported) as long as at least one item applied

**Non-functional:**
- Atomic mode switch via ArcSwap (in-flight requests see old or new state, never partial)
- Validate all names before applying any (fail-fast on invalid scope/mode)
- < 1ms for typical set_profile (pure in-memory HashMap swap)

## Architecture

```
POST /__waf_control/set_profile
  -> benchmark_secret_guard
  -> set_profile_handler:
     1. Parse + validate request body (scope, mode, features/policies)
     2. Validate names against FeatureCatalog -> (supported, unsupported)
     3. Apply to ModeRegistry based on scope:
        - "all"      -> registry.set_all(mode)
        - "features" -> registry.set_features(&supported, mode)
        - "policies" -> registry.set_policies(feature, &supported, mode)
     4. Snapshot current state for response
     5. Return { ok, action, applied, active, unsupported, ts_ms }
```

### Request Body Variants

```rust
#[derive(Deserialize)]
#[serde(tag = "scope")]
enum SetProfileRequest {
    #[serde(rename = "all")]
    All { mode: String },
    #[serde(rename = "features")]
    Features { mode: String, features: Vec<String> },
    #[serde(rename = "policies")]
    Policies { mode: String, feature: String, policies: Vec<String> },
}
```

### Response Schema (contract 2.5)

```json
{
  "ok": true,
  "action": "set_profile",
  "applied": {
    "scope": "features",
    "mode": "log_only",
    "features": ["access_control"]
  },
  "active": {
    "default_mode": "enforce",
    "overrides": {
      "access_control": "log_only"
    }
  },
  "unsupported": [],
  "ts_ms": 1777363201123
}
```

## Related Code Files

**Modify:**
- `crates/waf-api/src/interop_control.rs` — replace stub `set_profile_handler`

**Read (dependencies):**
- `crates/waf-engine/src/interop/mode_registry.rs` (Phase 1)
- `crates/waf-engine/src/interop/feature_catalog.rs` (Phase 1)

**Create:**
- `crates/waf-api/tests/interop_control_set_profile.rs`

## Implementation Steps

### TDD: Write Tests First

1. Create `crates/waf-api/tests/interop_control_set_profile.rs`:

```rust
// Test: scope "all" + mode "log_only" sets global default
#[tokio::test]
async fn set_profile_all_log_only() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "all", "mode": "log_only"
    })).await;
    assert_eq!(resp.status(), 200);
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["action"], "set_profile");
    assert_eq!(body["active"]["default_mode"], "log_only");
    assert_eq!(body["active"]["overrides"], json!({})); // cleared
}

// Test: scope "all" + mode "enforce" clears overrides
#[tokio::test]
async fn set_profile_all_enforce_clears_overrides() {
    let app = test_app_with_interop();
    // Pre-set override
    app.mode_registry().set_feature("injection_control", InteropMode::LogOnly);
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "all", "mode": "enforce"
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["active"]["default_mode"], "enforce");
    assert_eq!(body["active"]["overrides"], json!({}));
}

// Test: scope "features" applies only listed features
#[tokio::test]
async fn set_profile_features_selective() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["injection_control", "rate_limiting"]
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    let overrides = &body["active"]["overrides"];
    assert_eq!(overrides["injection_control"], "log_only");
    assert_eq!(overrides["rate_limiting"], "log_only");
    // Unmentioned features not in overrides
    assert!(overrides.get("bot_detection").is_none());
}

// Test: scope "policies" applies policies under one feature
#[tokio::test]
async fn set_profile_policies_selective() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "policies",
        "mode": "log_only",
        "feature": "injection_control",
        "policies": ["sqli", "xss"]
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    let overrides = &body["active"]["overrides"];
    assert_eq!(overrides["injection_control.sqli"], "log_only");
    assert_eq!(overrides["injection_control.xss"], "log_only");
}

// Test: unsupported features reported in response
#[tokio::test]
async fn set_profile_unsupported_features() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["injection_control", "nonexistent_feature"]
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    let unsupported: Vec<String> = body["unsupported"].as_array().unwrap()
        .iter().map(|v| v.as_str().unwrap().to_string()).collect();
    assert!(unsupported.contains(&"nonexistent_feature".to_string()));
    // injection_control still applied
    assert_eq!(body["active"]["overrides"]["injection_control"], "log_only");
}

// Test: unsupported policies reported
#[tokio::test]
async fn set_profile_unsupported_policies() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "policies",
        "mode": "log_only",
        "feature": "injection_control",
        "policies": ["sqli", "nonexistent_policy"]
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    let unsupported = body["unsupported"].as_array().unwrap();
    assert_eq!(unsupported.len(), 1);
}

// Test: invalid mode returns 400
#[tokio::test]
async fn set_profile_invalid_mode() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "all", "mode": "invalid"
    })).await;
    assert_eq!(resp.status(), 400);
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], false);
}

// Test: invalid scope returns 400
#[tokio::test]
async fn set_profile_invalid_scope() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "invalid", "mode": "enforce"
    })).await;
    assert_eq!(resp.status(), 400);
}

// Test: scope "features" without features array returns 400
#[tokio::test]
async fn set_profile_features_missing_array() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features", "mode": "log_only"
    })).await;
    assert_eq!(resp.status(), 400);
}

// Test: scope "policies" without feature field returns 400
#[tokio::test]
async fn set_profile_policies_missing_feature() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "policies", "mode": "log_only", "policies": ["sqli"]
    })).await;
    assert_eq!(resp.status(), 400);
}

// Test: applied field echoes request
#[tokio::test]
async fn set_profile_applied_echoes_request() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["injection_control"]
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["applied"]["scope"], "features");
    assert_eq!(body["applied"]["mode"], "log_only");
    assert_eq!(body["applied"]["features"], json!(["injection_control"]));
}

// Test: ts_ms is valid epoch milliseconds
#[tokio::test]
async fn set_profile_ts_ms() {
    let before = epoch_ms_now();
    let body = authed_post_json(&app, "/__waf_control/set_profile", json!({
        "scope": "all", "mode": "enforce"
    })).await;
    let after = epoch_ms_now();
    let ts = body["ts_ms"].as_i64().unwrap();
    assert!(ts >= before && ts <= after);
}

// Test: all unsupported -> still ok:true with empty applied effect
#[tokio::test]
async fn set_profile_all_unsupported_still_ok() {
    let app = test_app_with_interop();
    let resp = authed_post(&app, "/__waf_control/set_profile", json!({
        "scope": "features",
        "mode": "log_only",
        "features": ["nonexistent1", "nonexistent2"]
    })).await;
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], true);
    assert_eq!(body["unsupported"].as_array().unwrap().len(), 2);
}
```

### Implement

2. Define request parsing types (in `interop_control.rs` or a sub-module):

```rust
#[derive(Debug, Deserialize)]
struct SetProfileRequest {
    scope: String,
    mode: String,
    #[serde(default)]
    features: Option<Vec<String>>,
    #[serde(default)]
    feature: Option<String>,
    #[serde(default)]
    policies: Option<Vec<String>>,
}
```

3. Replace `set_profile_handler` stub in `interop_control.rs`:

```rust
async fn set_profile_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetProfileRequest>,
) -> impl IntoResponse {
    // 1. Validate mode
    let mode = match InteropMode::from_contract_str(&req.mode) {
        Some(m) => m,
        None => return (StatusCode::BAD_REQUEST, Json(json!({
            "ok": false,
            "error": format!("invalid mode: '{}'. Must be 'enforce' or 'log_only'", req.mode)
        }))).into_response(),
    };

    // 2. Dispatch by scope
    let (applied, unsupported) = match req.scope.as_str() {
        "all" => {
            state.mode_registry.set_all(mode);
            (json!({ "scope": "all", "mode": req.mode }), vec![])
        }
        "features" => {
            let features = match &req.features {
                Some(f) if !f.is_empty() => f,
                _ => return (StatusCode::BAD_REQUEST, Json(json!({
                    "ok": false,
                    "error": "scope 'features' requires non-empty 'features' array"
                }))).into_response(),
            };
            let (supported, unsupported) = FeatureCatalog::validate_features(features);
            if !supported.is_empty() {
                let refs: Vec<&str> = supported.iter().map(|s| s.as_str()).collect();
                state.mode_registry.set_features(&refs, mode);
            }
            (json!({
                "scope": "features",
                "mode": req.mode,
                "features": features,
            }), unsupported)
        }
        "policies" => {
            let feature = match &req.feature {
                Some(f) if !f.is_empty() => f.as_str(),
                _ => return (StatusCode::BAD_REQUEST, Json(json!({
                    "ok": false,
                    "error": "scope 'policies' requires 'feature' field"
                }))).into_response(),
            };
            let policies = match &req.policies {
                Some(p) if !p.is_empty() => p,
                _ => return (StatusCode::BAD_REQUEST, Json(json!({
                    "ok": false,
                    "error": "scope 'policies' requires non-empty 'policies' array"
                }))).into_response(),
            };
            let (supported, unsupported) = FeatureCatalog::validate_policies(feature, policies);
            if !supported.is_empty() {
                let refs: Vec<&str> = supported.iter().map(|s| s.as_str()).collect();
                state.mode_registry.set_policies(feature, &refs, mode);
            }
            (json!({
                "scope": "policies",
                "mode": req.mode,
                "feature": feature,
                "policies": policies,
            }), unsupported)
        }
        other => return (StatusCode::BAD_REQUEST, Json(json!({
            "ok": false,
            "error": format!("invalid scope: '{}'. Must be 'all', 'features', or 'policies'", other)
        }))).into_response(),
    };

    // 3. Snapshot current state
    let snap = state.mode_registry.snapshot();
    let mut overrides = serde_json::Map::new();
    for (k, v) in &snap.feature_overrides {
        overrides.insert(k.clone(), json!(v.as_contract_str()));
    }
    for (k, v) in &snap.policy_overrides {
        overrides.insert(k.clone(), json!(v.as_contract_str()));
    }

    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;

    Json(json!({
        "ok": true,
        "action": "set_profile",
        "applied": applied,
        "active": {
            "default_mode": snap.default_mode.as_contract_str(),
            "overrides": overrides,
        },
        "unsupported": unsupported,
        "ts_ms": ts_ms,
    })).into_response()
}
```

### Validate

4. `cargo check --workspace`
5. `cargo test -p waf-api --test interop_control_set_profile`
6. `cargo clippy --workspace -- -D warnings`

## Success Criteria

- [ ] `scope: "all"` sets default mode and clears all overrides
- [ ] `scope: "features"` sets only listed features
- [ ] `scope: "policies"` sets only listed policies under one feature
- [ ] Unsupported features/policies returned in `unsupported[]`
- [ ] Invalid mode/scope returns 400 with `ok: false`
- [ ] Missing required fields returns 400
- [ ] `applied` field echoes the request
- [ ] `active` reflects post-apply state from ModeRegistry snapshot
- [ ] `ts_ms` is valid epoch milliseconds
- [ ] Lenient mode: ok:true even when some items unsupported
- [ ] `cargo check --workspace` passes
- [ ] All 12+ tests pass

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Request body parsing ambiguity | Medium | Use flat struct with `scope` string dispatch, not serde tagged enum (simpler error messages) |
| Race between set_profile and capabilities read | Low | ArcSwap atomic swap; readers see old or new, never partial |
| Unsupported feature validation drift | Medium | `FeatureCatalog::validate_*` is single source of truth; new features must register |
| Empty features array treated as no-op | Low | Explicit check for non-empty; return 400 if empty |
