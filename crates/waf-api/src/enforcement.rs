//! JWT-guarded `/api/enforcement/*` routes.
//!
//! These mirror the secret-gated `/__waf_control/*` control plane so the
//! operator browser authenticates with its existing Bearer JWT instead of
//! holding `X-Benchmark-Secret`. Handler logic lives in `interop_control`; these
//! handlers only enforce the interop-disabled gate and delegate, guaranteeing
//! byte-identical response shapes across both route groups.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::interop_control::{
    SetProfileRequest, capabilities_value, flush_cache_value, reset_state_value, set_profile_value,
};
use crate::state::AppState;

/// Response when interop is disabled. Mirrors the secret plane's 404 so the
/// frontend's "control plane disabled" Result branch is exercised identically.
fn disabled_response() -> Response {
    (StatusCode::NOT_FOUND, Json(json!({"ok": false, "error": "interop disabled"}))).into_response()
}

pub(crate) async fn enforcement_capabilities(State(state): State<Arc<AppState>>) -> Response {
    if !state.interop_config.enabled {
        return disabled_response();
    }
    Json(capabilities_value(&state)).into_response()
}

pub(crate) async fn enforcement_set_profile(State(state): State<Arc<AppState>>, Json(req): Json<SetProfileRequest>) -> Response {
    if !state.interop_config.enabled {
        return disabled_response();
    }
    let (status, body) = set_profile_value(&state, &req);
    (status, Json(body)).into_response()
}

pub(crate) async fn enforcement_reset_state(State(state): State<Arc<AppState>>) -> Response {
    if !state.interop_config.enabled {
        return disabled_response();
    }
    Json(reset_state_value(&state).await).into_response()
}

pub(crate) async fn enforcement_flush_cache(State(state): State<Arc<AppState>>) -> Response {
    if !state.interop_config.enabled {
        return disabled_response();
    }
    Json(flush_cache_value(&state).await).into_response()
}
