---
phase: 2
title: "Benchmark Auth Middleware"
status: completed
priority: P1
effort: "2-3h"
dependencies: []
---

# Phase 2: Benchmark Auth Middleware

## Overview

Implement `X-Benchmark-Secret` header authentication as an Axum middleware scoped to the `/__waf_control/*` route group. Uses constant-time comparison to prevent timing side-channel attacks. Configurable via `[interop]` TOML section.

## Context Links

- Contract §2.2: `analysis/docs/EN_waf_interop_contract_v2.3.md` lines 46–53
- Architecture report: `plans/reports/researcher-260528-2206-waf-control-interface-architecture-patterns-report.md` §2
- Existing auth middleware pattern: `crates/waf-api/src/middleware.rs`
- Existing config: `crates/waf-common/src/config.rs`
- Router wiring: `crates/waf-api/src/server.rs:59–280`

## Requirements

**Functional:**
- All `/__waf_control/*` routes require `X-Benchmark-Secret` header
- Missing header → `403 Forbidden` with `{"ok": false, "error": "missing benchmark secret"}`
- Wrong value → `403 Forbidden` with `{"ok": false, "error": "invalid benchmark secret"}`
- Correct value → request passes through unchanged
- Secret configurable via `[interop] benchmark_secret` in TOML (default: `"waf-hackathon-2026-ctrl"`)

**Non-functional:**
- Constant-time comparison (prevent timing attacks)
- No interference with existing JWT middleware on `/api/*` routes
- No interference with public `/health` route

**Security:**
- Secret value never logged (even at DEBUG level)
- Comparison uses `subtle::ConstantTimeEq` or equivalent
- Response body is generic (doesn't leak which part failed)

## Architecture

```
/__waf_control/* route group
  └─ .layer(from_fn_with_state(state, benchmark_secret_guard))
     ├─ Extract X-Benchmark-Secret header
     ├─ Compare with state.interop_config.benchmark_secret (constant-time)
     ├─ Pass → next.run(req)
     └─ Fail → 403 JSON response
```

## Related Code Files

**Create:**
- `crates/waf-api/src/interop_control.rs` — route group + middleware + handler stubs
- `crates/waf-api/tests/interop_control_auth.rs` — auth middleware tests

**Modify:**
- `crates/waf-common/src/config.rs` — add `InteropConfig` struct + `interop` field on `AppConfig`
- `crates/waf-api/src/state.rs` — add `interop_config: InteropConfig` field
- `crates/waf-api/src/server.rs` — mount `/__waf_control` route group
- `crates/waf-api/src/lib.rs` — add `pub mod interop_control;`

## Implementation Steps

### TDD: Write Tests First

1. Create `crates/waf-api/tests/interop_control_auth.rs`:

```rust
// Test: missing X-Benchmark-Secret returns 403
#[tokio::test]
async fn missing_secret_returns_403() {
    let app = test_app_with_interop();
    let resp = app.get("/__waf_control/capabilities").await;
    assert_eq!(resp.status(), 403);
    let body: Value = resp.json().await;
    assert_eq!(body["ok"], false);
}

// Test: wrong X-Benchmark-Secret returns 403
#[tokio::test]
async fn wrong_secret_returns_403() {
    let app = test_app_with_interop();
    let resp = app
        .get("/__waf_control/capabilities")
        .header("X-Benchmark-Secret", "wrong-value")
        .await;
    assert_eq!(resp.status(), 403);
}

// Test: correct secret passes through
#[tokio::test]
async fn correct_secret_passes() {
    let app = test_app_with_interop();
    let resp = app
        .get("/__waf_control/capabilities")
        .header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
        .await;
    assert_ne!(resp.status(), 403);
}

// Test: case-sensitive comparison
#[tokio::test]
async fn secret_is_case_sensitive() {
    let app = test_app_with_interop();
    let resp = app
        .get("/__waf_control/capabilities")
        .header("X-Benchmark-Secret", "WAF-HACKATHON-2026-CTRL")
        .await;
    assert_eq!(resp.status(), 403);
}

// Test: JWT auth NOT required on control routes
#[tokio::test]
async fn control_routes_bypass_jwt() {
    let app = test_app_with_interop();
    let resp = app
        .get("/__waf_control/capabilities")
        .header("X-Benchmark-Secret", "waf-hackathon-2026-ctrl")
        .await;
    assert_ne!(resp.status(), 401); // No JWT needed
}

// Test: existing /api/* routes still require JWT (no regression)
#[tokio::test]
async fn api_routes_still_require_jwt() {
    let app = test_app_with_interop();
    let resp = app.get("/api/hosts").await;
    assert_eq!(resp.status(), 401);
}
```

### Implement

2. Add `InteropConfig` to `crates/waf-common/src/config.rs`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InteropConfig {
    #[serde(default = "default_benchmark_secret")]
    pub benchmark_secret: String,
    #[serde(default = "default_interop_enabled")]
    pub enabled: bool,
}

fn default_benchmark_secret() -> String {
    "waf-hackathon-2026-ctrl".to_string()
}

const fn default_interop_enabled() -> bool {
    true
}

impl Default for InteropConfig {
    fn default() -> Self {
        Self {
            benchmark_secret: default_benchmark_secret(),
            enabled: default_interop_enabled(),
        }
    }
}
```

Add `#[serde(default)] pub interop: InteropConfig` to `AppConfig`.

3. Add `interop_config: InteropConfig` to `AppState` struct and wire in `AppState::new()`.

4. Create `crates/waf-api/src/interop_control.rs`:

```rust
use axum::{
    Router, Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::sync::Arc;
use crate::state::AppState;

pub fn interop_control_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/capabilities", get(capabilities_handler))
        .route("/reset_state", post(reset_state_handler))
        .route("/set_profile", post(set_profile_handler))
        .route("/flush_cache", post(flush_cache_handler))
        .layer(middleware::from_fn_with_state(
            // state passed via Router::with_state — middleware receives it
            benchmark_secret_guard,
        ))
}

async fn benchmark_secret_guard(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !state.interop_config.enabled {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "error": "interop disabled"})))
            .into_response();
    }

    let expected = state.interop_config.benchmark_secret.as_bytes();
    let provided = req
        .headers()
        .get("x-benchmark-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Constant-time comparison to prevent timing attacks
    if provided.len() != expected.len()
        || !constant_time_eq(provided.as_bytes(), expected)
    {
        return (StatusCode::FORBIDDEN, Json(json!({
            "ok": false,
            "error": "invalid or missing benchmark secret"
        })))
        .into_response();
    }

    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// Stub handlers (implemented in later phases)
async fn capabilities_handler() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"ok": false, "error": "not yet implemented"})))
}
async fn reset_state_handler() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"ok": false, "error": "not yet implemented"})))
}
async fn set_profile_handler() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"ok": false, "error": "not yet implemented"})))
}
async fn flush_cache_handler() -> impl IntoResponse {
    (StatusCode::NOT_IMPLEMENTED, Json(json!({"ok": false, "error": "not yet implemented"})))
}
```

5. Mount in `crates/waf-api/src/server.rs`:
   ```rust
   .nest("/__waf_control", interop_control::interop_control_routes())
   ```
   Place BEFORE `.layer(security_headers_middleware)` in the merge chain, after `ws_routes`.

6. Add `pub mod interop_control;` to `crates/waf-api/src/lib.rs`.

### Validate

7. `cargo check --workspace`
8. `cargo test -p waf-api --test interop_control_auth`
9. `cargo clippy --workspace -- -D warnings`

## Success Criteria

- [ ] Missing `X-Benchmark-Secret` → 403 with JSON body
- [ ] Wrong secret → 403 with JSON body
- [ ] Correct secret → request passes to handler
- [ ] Comparison is constant-time (XOR-based, not short-circuit)
- [ ] `InteropConfig` in TOML with default secret
- [ ] `[interop] enabled = false` disables all control routes (404)
- [ ] Existing JWT routes unaffected (regression test)
- [ ] `cargo check --workspace` passes

## Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| Secret leaked in logs | High | Never log the secret value; log "auth passed/failed" only |
| Timing attack on comparison | Medium | XOR-based constant-time; length check uses separate early return (acceptable: length itself is not secret) |
| Middleware applied too broadly | High | Scoped to `/__waf_control` route group only via `nest()` |
