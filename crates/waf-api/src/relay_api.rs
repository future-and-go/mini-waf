//! Relay & Proxy Intel API — GET/PUT /api/relay/config,
//! GET /api/relay/intel/status, POST /api/relay/intel/refresh,
//! POST /api/relay/test.
//!
//! Config source: `configs/relay.yaml`.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn resolve_path(state: &AppState, relative: &str) -> std::path::PathBuf {
    state.main_config_file.as_ref().map_or_else(
        || std::path::PathBuf::from(relative),
        |main| {
            let p = std::path::Path::new(main.as_str());
            let root = p
                .parent()
                .and_then(|c| c.parent())
                .unwrap_or_else(|| std::path::Path::new("."));
            root.join(relative)
        },
    )
}

async fn read_yaml_opt(path: &std::path::Path) -> Option<Value> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    serde_yaml::from_str::<Value>(&raw).ok()
}

async fn write_yaml(path: &std::path::Path, value: &Value) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let s = serde_yaml::to_string(value).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, s.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

fn default_relay_config() -> Value {
    json!({
        "enabled": false,
        "providers": {
            "asn_classifier": { "enabled": true, "risk_weight": 15 },
            "tor_exit": { "enabled": true, "risk_weight": 30 },
            "datacenter": { "enabled": true, "risk_weight": 15 },
            "proxy_chain": { "enabled": true, "risk_weight": 20 },
            "xff_validator": { "enabled": true, "risk_weight": 10, "max_chain_depth": 3, "reject_private_in_chain": false }
        },
        "intel": {
            "asn_feed": { "url": "", "refresh_secs": 86400 },
            "tor_feed": { "url": "https://check.torproject.org/torbulkexitlist", "refresh_secs": 3600 },
            "datacenter_set": { "path": "" }
        },
        "trusted_proxies": [],
        "risk_weights": { "tor": 30, "datacenter": 15, "bad_asn": 25 }
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_relay_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/relay.yaml");
    let cfg = read_yaml_opt(&path).await.unwrap_or_else(default_relay_config);
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_relay_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/relay.yaml");
    write_yaml(&path, &body).await?;
    Ok(Json(json!({ "success": true, "data": body })))
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

/// **STUB — v1 placeholder.**  Echoes `client_ip` with empty verdicts; real relay
/// classification is not yet plumbed through the test path.  Frontend should treat
/// `verdicts: []` as "classification unavailable" rather than "IP is clean".
/// Will be wired to the live relay-intel engine in a future release.
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
