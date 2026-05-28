//! `DDoS` protection API — GET/PUT /api/ddos/config, GET /api/ddos/metrics,
//! GET /api/ddos/ban-table, DELETE /api/ddos/ban-table/:ip.
//!
//! Config source: `configs/ddos.yaml`. Ban-table is in-memory only (no persistence yet).

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
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

fn yaml_to_fe(v: &Value) -> Value {
    let per_ip = v.get("per_ip").cloned().unwrap_or(Value::Null);
    let fingerprint_cfg = v.get("per_fingerprint").cloned().unwrap_or(Value::Null);
    let store = v.get("store").cloned().unwrap_or(Value::Null);
    let bans = v.get("ban_durations_secs").and_then(Value::as_array).map_or_else(
        || vec![60, 300, 3600],
        |a| a.iter().filter_map(Value::as_i64).collect::<Vec<_>>(),
    );
    json!({
        "enabled": v.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        "per_ip": {
            "threshold_rps": per_ip.get("threshold_rps").and_then(Value::as_i64).unwrap_or(100),
            "window_secs": per_ip.get("window_secs").and_then(Value::as_i64).unwrap_or(10)
        },
        "per_fingerprint": {
            "threshold_rps": fingerprint_cfg.get("threshold_rps").and_then(Value::as_i64).unwrap_or(200),
            "window_secs": fingerprint_cfg.get("window_secs").and_then(Value::as_i64).unwrap_or(10)
        },
        "ban_durations_secs": bans,
        "store": {
            "backend": store.get("backend").and_then(Value::as_str).unwrap_or("memory"),
            "redis_url": store.get("redis_url").and_then(Value::as_str).unwrap_or("")
        }
    })
}

fn default_ddos_fe() -> Value {
    json!({
        "enabled": true,
        "per_ip": { "threshold_rps": 100, "window_secs": 10 },
        "per_fingerprint": { "threshold_rps": 200, "window_secs": 10 },
        "ban_durations_secs": [60, 300, 3600],
        "store": { "backend": "memory", "redis_url": "" }
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_ddos_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/ddos.yaml");
    let cfg = read_yaml_opt(&path)
        .await
        .map_or_else(default_ddos_fe, |v| yaml_to_fe(&v));
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_ddos_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/ddos.yaml");
    let store = body.get("store").cloned().unwrap_or(Value::Null);
    let yaml_val = json!({
        "enabled": body.get("enabled"),
        "per_ip": body.get("per_ip"),
        "per_fingerprint": body.get("per_fingerprint"),
        "ban_durations_secs": body.get("ban_durations_secs"),
        "store": {
            "backend": store.get("backend"),
            "redis_url": store.get("redis_url")
        }
    });
    write_yaml(&path, &yaml_val).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn get_ddos_metrics(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "success": true,
        "data": { "active_bans": 0, "bursts_1h": 0, "bans_issued_1h": 0, "store_errors": 0 }
    })))
}

/// **STUB — v1 placeholder.**  Returns an empty ban table; in-memory DDoS ban
/// tracking is not yet wired into the API layer.  Frontend should treat `data: []`
/// as "no data available" rather than "no active bans".  Will be backed by the
/// live ban store in a future release.
pub async fn list_ban_table(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

pub async fn delete_ban_entry(_: State<Arc<AppState>>, Path(ip): Path<String>) -> impl IntoResponse {
    tracing::info!("Manual unban: {}", ip);
    (StatusCode::OK, Json(json!({ "success": true, "data": { "ip": ip } }))).into_response()
}
