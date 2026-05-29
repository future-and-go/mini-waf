use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::json;
use waf_engine::interop::{FeatureCatalog, InteropMode};

use crate::state::AppState;

/// Build the `/__waf_control/*` route group.
pub fn interop_control_routes(state: Arc<AppState>) -> Router<Arc<AppState>> {
    Router::new()
        .route("/capabilities", get(capabilities_handler))
        .route("/reset_state", post(reset_state_handler))
        .route("/set_profile", post(set_profile_handler))
        .route("/flush_cache", post(flush_cache_handler))
        .route_layer(axum::middleware::from_fn_with_state(state, benchmark_secret_guard))
}

/// Validates the `X-Benchmark-Secret` header using constant-time comparison.
pub async fn benchmark_secret_guard(State(state): State<Arc<AppState>>, req: Request<Body>, next: Next) -> Response {
    if !state.interop_config.enabled {
        return (StatusCode::NOT_FOUND, Json(json!({"ok": false, "error": "not found"}))).into_response();
    }

    let expected = state.interop_config.benchmark_secret.as_bytes();
    let provided = req.headers().get("x-benchmark-secret").and_then(|v| v.to_str().ok());

    let is_valid = provided.is_some_and(|val| constant_time_eq(val.as_bytes(), expected));

    if !is_valid {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({
                "ok": false,
                "error": "invalid or missing benchmark secret"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len_diff = a.len() ^ b.len();
    let mut diff = u8::from(len_diff != 0);
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn epoch_ms_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn build_active_snapshot(state: &AppState) -> serde_json::Value {
    let snap = state.mode_registry.snapshot();
    let mut overrides = serde_json::Map::new();
    for (k, v) in &snap.feature_overrides {
        overrides.insert(k.clone(), json!(v.as_contract_str()));
    }
    for (k, v) in &snap.policy_overrides {
        overrides.insert(k.clone(), json!(v.as_contract_str()));
    }
    json!({
        "default_mode": snap.default_mode.as_contract_str(),
        "overrides": overrides,
    })
}

// ── GET /capabilities ────────────────────────────────────────────────────────

async fn capabilities_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let catalog = FeatureCatalog::all();

    let mut features = serde_json::Map::new();
    for (name, info) in &catalog {
        features.insert(
            (*name).to_string(),
            json!({
                "supported": info.supported,
                "toggleable": info.toggleable,
                "policies": info.policies,
            }),
        );
    }

    Json(json!({
        "ok": true,
        "features": features,
        "active": build_active_snapshot(&state),
    }))
}

// ── POST /reset_state ────────────────────────────────────────────────────────

async fn reset_state_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.engine.reset_runtime_state();
    state.cache.flush().await;
    if let Some(cc) = &state.crowdsec_cache {
        cc.clear_all();
    }
    state.mode_registry.reset();

    Json(json!({
        "ok": true,
        "action": "reset_state",
        "audit_log_preserved": true,
        "ts_ms": epoch_ms_now(),
    }))
}

// ── POST /set_profile ────────────────────────────────────────────────────────

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

async fn set_profile_handler(State(state): State<Arc<AppState>>, Json(req): Json<SetProfileRequest>) -> Response {
    let Some(mode) = InteropMode::from_contract_str(&req.mode) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "ok": false,
                "error": format!("invalid mode: '{}'. Must be 'enforce' or 'log_only'", req.mode)
            })),
        )
            .into_response();
    };

    let (applied, unsupported) = match req.scope.as_str() {
        "all" => {
            state.mode_registry.set_all(mode);
            (json!({"scope": "all", "mode": req.mode}), vec![])
        }
        "features" => {
            let features = match &req.features {
                Some(f) if !f.is_empty() => f,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "ok": false,
                            "error": "scope 'features' requires non-empty 'features' array"
                        })),
                    )
                        .into_response();
                }
            };
            let (supported, unsupported) = FeatureCatalog::validate_features(features);
            if !supported.is_empty() {
                let refs: Vec<&str> = supported.iter().map(String::as_str).collect();
                state.mode_registry.set_features(&refs, mode);
            }
            (
                json!({
                    "scope": "features",
                    "mode": req.mode,
                    "features": features,
                }),
                unsupported,
            )
        }
        "policies" => {
            let feature = match &req.feature {
                Some(f) if !f.is_empty() => f.as_str(),
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "ok": false,
                            "error": "scope 'policies' requires 'feature' field"
                        })),
                    )
                        .into_response();
                }
            };
            let policies = match &req.policies {
                Some(p) if !p.is_empty() => p,
                _ => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({
                            "ok": false,
                            "error": "scope 'policies' requires non-empty 'policies' array"
                        })),
                    )
                        .into_response();
                }
            };
            let (supported, unsupported) = FeatureCatalog::validate_policies(feature, policies);
            if !supported.is_empty() {
                let refs: Vec<&str> = supported.iter().map(String::as_str).collect();
                state.mode_registry.set_policies(feature, &refs, mode);
            }
            (
                json!({
                    "scope": "policies",
                    "mode": req.mode,
                    "feature": feature,
                    "policies": policies,
                }),
                unsupported,
            )
        }
        other => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "ok": false,
                    "error": format!("invalid scope: '{other}'. Must be 'all', 'features', or 'policies'")
                })),
            )
                .into_response();
        }
    };

    Json(json!({
        "ok": true,
        "action": "set_profile",
        "applied": applied,
        "active": build_active_snapshot(&state),
        "unsupported": unsupported,
        "ts_ms": epoch_ms_now(),
    }))
    .into_response()
}

// ── POST /flush_cache ────────────────────────────────────────────────────────

async fn flush_cache_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    state.cache.flush().await;

    Json(json!({
        "ok": true,
        "action": "flush_cache",
        "ts_ms": epoch_ms_now(),
    }))
}
