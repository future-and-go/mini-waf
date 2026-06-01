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

use waf_engine::checks::ddos::config::{DdosDocument, DdosFileConfig};

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

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_ddos_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/ddos.yaml");
    let doc = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => serde_yaml::from_str::<DdosDocument>(&raw)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("parse ddos config: {e}")))?,
        Err(_) => DdosDocument::default(),
    };
    let data = serde_json::to_value(&doc.ddos)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize ddos config: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

pub async fn put_ddos_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let cfg: DdosFileConfig =
        serde_json::from_value(body).map_err(|e| ApiError::BadRequest(format!("invalid ddos config: {e}")))?;
    cfg.validate()
        .map_err(|e| ApiError::BadRequest(format!("ddos config validation: {e}")))?;
    let doc = DdosDocument { ddos: cfg };
    let path = resolve_path(&state, "configs/ddos.yaml");
    let yaml_str =
        serde_yaml::to_string(&doc).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize yaml: {e}")))?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, yaml_str.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, &path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    let data =
        serde_json::to_value(&doc.ddos).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize response: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

pub async fn get_ddos_metrics(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "success": true,
        "data": { "active_bans": 0, "bursts_1h": 0, "bans_issued_1h": 0, "store_errors": 0 }
    })))
}

/// **STUB — v1 placeholder.**
///
/// Returns an empty ban table; in-memory `DDoS` ban tracking is not yet wired
/// into the API layer. Frontend should treat `data: []` as "no data available"
/// rather than "no active bans". Will be backed by the live ban store in a
/// future release.
pub async fn list_ban_table(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

pub async fn delete_ban_entry(_: State<Arc<AppState>>, Path(ip): Path<String>) -> impl IntoResponse {
    tracing::info!("Manual unban: {}", ip);
    (StatusCode::OK, Json(json!({ "success": true, "data": { "ip": ip } }))).into_response()
}
