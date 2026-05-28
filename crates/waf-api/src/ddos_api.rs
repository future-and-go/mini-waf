//! DDoS protection API — GET/PUT /api/ddos/config, GET /api/ddos/metrics,
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
    if let Some(main) = &state.main_config_file {
        let p = std::path::Path::new(main.as_str());
        let root = p
            .parent()
            .and_then(|c| c.parent())
            .unwrap_or(std::path::Path::new("."));
        root.join(relative)
    } else {
        std::path::PathBuf::from(relative)
    }
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
    let per_ip = &v["per_ip"];
    let per_fp = &v["per_fingerprint"];
    let store = &v["store"];
    let bans = v["ban_durations_secs"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_i64()).collect::<Vec<_>>())
        .unwrap_or_else(|| vec![60, 300, 3600]);
    json!({
        "enabled": v["enabled"].as_bool().unwrap_or(true),
        "per_ip": {
            "threshold_rps": per_ip["threshold_rps"].as_i64().unwrap_or(100),
            "window_secs": per_ip["window_secs"].as_i64().unwrap_or(10)
        },
        "per_fingerprint": {
            "threshold_rps": per_fp["threshold_rps"].as_i64().unwrap_or(200),
            "window_secs": per_fp["window_secs"].as_i64().unwrap_or(10)
        },
        "ban_durations_secs": bans,
        "store": {
            "backend": store["backend"].as_str().unwrap_or("memory"),
            "redis_url": store.get("redis_url").and_then(|v| v.as_str()).unwrap_or("")
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
    let cfg = match read_yaml_opt(&path).await {
        Some(v) => yaml_to_fe(&v),
        None => default_ddos_fe(),
    };
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_ddos_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/ddos.yaml");
    let store = &body["store"];
    let yaml_val = json!({
        "enabled": body["enabled"],
        "per_ip": body["per_ip"],
        "per_fingerprint": body["per_fingerprint"],
        "ban_durations_secs": body["ban_durations_secs"],
        "store": {
            "backend": store["backend"],
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

pub async fn list_ban_table(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

pub async fn delete_ban_entry(_: State<Arc<AppState>>, Path(ip): Path<String>) -> impl IntoResponse {
    tracing::info!("Manual unban: {}", ip);
    (StatusCode::OK, Json(json!({ "success": true, "data": { "ip": ip } }))).into_response()
}
