//! Relay & Proxy Intel API — GET/PUT /api/relay/config,
//! GET /api/relay/intel/status, POST /api/relay/intel/refresh,
//! POST /api/relay/test.
//!
//! Config source: `configs/relay.yaml`.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde_json::{Value, json};
use waf_engine::relay::config::{RelayConfig, RelayDetectionDocument};

use crate::config_files::{resolve_path, write_yaml_str};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_relay_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/relay.yaml");
    let doc = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => serde_yaml::from_str::<RelayDetectionDocument>(&raw)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("parse relay config: {e}")))?,
        Err(_) => RelayDetectionDocument::default(),
    };
    let data = serde_json::to_value(&doc.relay_detection)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize relay config: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

pub async fn put_relay_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let cfg: RelayConfig =
        serde_json::from_value(body).map_err(|e| ApiError::BadRequest(format!("invalid relay config: {e}")))?;
    cfg.validate()
        .map_err(|e| ApiError::BadRequest(format!("relay config validation: {e}")))?;
    let doc = RelayDetectionDocument { relay_detection: cfg };
    let path = resolve_path(&state, "configs/relay.yaml");
    let yaml_str =
        serde_yaml::to_string(&doc).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize yaml: {e}")))?;
    write_yaml_str(&path, &yaml_str).await?;
    let data = serde_json::to_value(&doc.relay_detection)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize response: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

pub async fn get_relay_intel_status(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "success": true,
        "data": {
            "tor": { "entry_count": 0, "last_refresh": null, "last_error": null },
            "asn": { "entry_count": 0, "last_refresh": null, "last_error": null },
            "datacenter": { "entry_count": 0, "last_refresh": null, "last_error": null }
        }
    })))
}

pub async fn refresh_relay_intel(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "success": true,
        "data": { "tor_loaded": 0, "asn_loaded": 0, "datacenter_loaded": 0, "took_ms": 0 }
    })))
}

/// **STUB — v1 placeholder.**
///
/// Echoes `client_ip` with empty verdicts; real relay classification is not yet
/// plumbed through the test path. Frontend should treat `verdicts: []` as
/// "classification unavailable" rather than "IP is clean". Will be wired to
/// the live relay-intel engine in a future release.
pub async fn test_relay(_: State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let client_ip = body.get("client_ip").and_then(Value::as_str).unwrap_or("unknown");
    Ok(Json(json!({
        "success": true,
        "data": {
            "client_ip": client_ip,
            "verdicts": [],
            "total_risk_delta": 0
        }
    })))
}
