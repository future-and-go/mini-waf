//! Transaction-velocity config API (C2, FR-012 / FR-031).
//!
//! `GET`/`PUT /api/tx-velocity/config` — read/write `configs/tx-velocity.yaml`.
//! Mirrors the `ddos_api` pattern: typed config, `{ success, data: <inner
//! object> }` envelope, atomic `.tmp` + rename write. The engine hot-reloads
//! the file via `start_tx_velocity_watcher` (wired in `main.rs`), so a PUT is
//! applied without restart (FR-031).

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{State, connect_info::ConnectInfo},
    http::{HeaderMap, header::AUTHORIZATION},
};
use serde_json::{Value, json};

use waf_engine::checks::tx_velocity::config::{TxVelocityDocument, TxVelocityFileConfig};

use crate::auth::validate_access_token;
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

fn bearer_username(headers: &HeaderMap, secret: &str) -> Option<String> {
    let token = headers.get(AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    validate_access_token(token, secret).ok().map(|c| c.sub)
}

/// `GET /api/tx-velocity/config` — current thresholds. Missing file → defaults.
pub async fn get_tx_velocity_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/tx-velocity.yaml");
    let doc = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => serde_yaml::from_str::<TxVelocityDocument>(&raw)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("parse tx-velocity config: {e}")))?,
        Err(_) => TxVelocityDocument::default(),
    };
    let data = serde_json::to_value(&doc.tx_velocity)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize tx-velocity config: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

/// `PUT /api/tx-velocity/config` — validate + persist + hot-reload.
pub async fn put_tx_velocity_config(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    // Parse-first into the typed inner config (rejects unknown keys / bad types).
    let inner: TxVelocityFileConfig =
        serde_json::from_value(body).map_err(|e| ApiError::BadRequest(format!("invalid tx-velocity config: {e}")))?;
    let doc = TxVelocityDocument { tx_velocity: inner };

    let yaml_str =
        serde_yaml::to_string(&doc).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize yaml: {e}")))?;

    // Validate through the engine's own parser (schema_version, bounds, regex
    // compile of endpoint_roles[].path) before any write — never half-write.
    TxVelocityFileConfig::from_yaml_str(&yaml_str)
        .map_err(|e| ApiError::BadRequest(format!("tx-velocity config validation: {e}")))?;

    let path = resolve_path(&state, "configs/tx-velocity.yaml");
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

    // Audit the config mutation.
    let admin_username = bearer_username(&headers, &state.jwt_secret);
    if let Err(e) = state
        .db
        .create_audit_log(
            admin_username.as_deref(),
            "tx-velocity.config.update",
            Some("tx_velocity_config"),
            None,
            Some(json!({ "enabled": doc.tx_velocity.enabled })),
            Some(&peer.ip().to_string()),
        )
        .await
    {
        tracing::warn!("failed to write audit log for tx-velocity config update: {e}");
    }

    let data = serde_json::to_value(&doc.tx_velocity)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize response: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}
