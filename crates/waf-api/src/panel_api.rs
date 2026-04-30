//! GET/PUT `/api/panel-config` — read/write `waf-panel.toml` for admin UI sync.

use std::sync::Arc;

use axum::{Json, extract::State};
use serde_json::{Value, json};
use waf_common::panel_config::WafPanelConfig;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

async fn panel_revision_secs(path: &std::path::Path) -> Result<u64, ApiError> {
    // Path validity was already enforced by the caller; failures here are
    // server-side IO problems (file removed under us, permission glitch, …),
    // so report them as Internal rather than BadRequest.
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("panel config metadata: {e}")))?;
    Ok(meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs()))
}

fn panel_json_response(
    cfg: &WafPanelConfig,
    revision: u64,
    path: &std::path::Path,
    main_config_file: Option<&str>,
) -> Value {
    json!({
        "success": true,
        "data": {
            "config": cfg,
            "revision": revision,
            "path": path.display().to_string(),
            "main_config_file": main_config_file,
        }
    })
}

pub async fn get_panel_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = state.panel_config_path.as_ref().ok_or_else(|| {
        ApiError::BadRequest("panel.config_path is not set in the main TOML ([panel] section).".into())
    })?;

    let revision = panel_revision_secs(path).await?;
    // Read failure here is server-side IO (file disappeared / permission).
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("read panel config file: {e}")))?;

    // Parse/validation errors reflect bad on-disk content; surface as 400 so
    // the operator sees the actual TOML mistake.
    let cfg = WafPanelConfig::from_toml_str(&raw).map_err(|e| ApiError::BadRequest(format!("{e}")))?;

    Ok(Json(panel_json_response(
        &cfg,
        revision,
        path,
        state.main_config_file.as_deref(),
    )))
}

pub async fn put_panel_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<WafPanelConfig>,
) -> ApiResult<Json<Value>> {
    let path = state.panel_config_path.as_ref().ok_or_else(|| {
        ApiError::BadRequest("panel.config_path is not set in the main TOML ([panel] section).".into())
    })?;

    cfg.validate().map_err(|e| ApiError::BadRequest(e.to_string()))?;

    let toml_out = cfg
        .to_toml_string()
        .map_err(|e| ApiError::BadRequest(format!("serialize panel config: {e}")))?;

    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("create panel config dir: {e}")))?;
    }

    tokio::fs::write(path, toml_out.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write panel config: {e}")))?;

    let revision = panel_revision_secs(path).await?;
    Ok(Json(panel_json_response(
        &cfg,
        revision,
        path,
        state.main_config_file.as_deref(),
    )))
}
