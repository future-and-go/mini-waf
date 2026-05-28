//! Access lists API — GET/PUT /api/access-lists, GET /api/access-lists/test.
//!
//! Config source: `rules/access-lists.yaml`. The YAML structure maps directly
//! to the FE `AccessConfig` interface (no wrapper key needed).

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn resolve_path(state: &AppState, relative: &str) -> std::path::PathBuf {
    if let Some(main) = &state.main_config_file {
        let p = std::path::Path::new(main.as_str());
        let root = p.parent().and_then(|c| c.parent()).unwrap_or(std::path::Path::new("."));
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

fn default_access_config() -> Value {
    json!({
        "version": 1,
        "dry_run": false,
        "ip_whitelist": [],
        "ip_blacklist": [],
        "host_whitelist": {
            "critical": [], "high": [], "medium": [], "catch_all": []
        },
        "tier_whitelist_mode": {
            "critical": "blacklist_only", "high": "blacklist_only",
            "medium": "full_bypass", "catch_all": "full_bypass"
        }
    })
}

fn yaml_to_fe(v: &Value) -> Value {
    let hw = &v["host_whitelist"];
    let twm = &v["tier_whitelist_mode"];
    json!({
        "version": v["version"].as_i64().unwrap_or(1),
        "dry_run": v["dry_run"].as_bool().unwrap_or(false),
        "ip_whitelist": v["ip_whitelist"].as_array().cloned().unwrap_or_default(),
        "ip_blacklist": v["ip_blacklist"].as_array().cloned().unwrap_or_default(),
        "host_whitelist": {
            "critical":  hw["critical"].as_array().cloned().unwrap_or_default(),
            "high":      hw["high"].as_array().cloned().unwrap_or_default(),
            "medium":    hw["medium"].as_array().cloned().unwrap_or_default(),
            "catch_all": hw["catch_all"].as_array().cloned().unwrap_or_default()
        },
        "tier_whitelist_mode": {
            "critical":  twm["critical"].as_str().unwrap_or("blacklist_only"),
            "high":      twm["high"].as_str().unwrap_or("blacklist_only"),
            "medium":    twm["medium"].as_str().unwrap_or("full_bypass"),
            "catch_all": twm["catch_all"].as_str().unwrap_or("full_bypass")
        }
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_access_lists(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "rules/access-lists.yaml");
    let cfg = match read_yaml_opt(&path).await {
        Some(v) => yaml_to_fe(&v),
        None => default_access_config(),
    };
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_access_lists(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "rules/access-lists.yaml");
    write_yaml(&path, &body).await?;
    // Reload engine rules so the live watcher picks up the change immediately
    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("access-lists: engine reload failed: {e}");
    }
    Ok(Json(json!({ "success": true, "data": body })))
}

#[derive(Deserialize)]
pub struct TestQuery {
    pub ip: Option<String>,
    pub host: Option<String>,
    pub tier: Option<String>,
}

pub async fn test_access_lists(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TestQuery>,
) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "rules/access-lists.yaml");
    let cfg = match read_yaml_opt(&path).await {
        Some(v) => yaml_to_fe(&v),
        None => default_access_config(),
    };

    let ip = q.ip.as_deref().unwrap_or("");
    let host = q.host.as_deref().unwrap_or("");
    let tier = q.tier.as_deref().unwrap_or("catch_all");

    // Check IP blacklist first
    let blacklist = cfg["ip_blacklist"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str().map_or(false, |s| s == ip)))
        .unwrap_or(false);
    if blacklist {
        return Ok(Json(json!({
            "success": true,
            "data": { "verdict": "block", "reason": "ip_blacklist" }
        })));
    }

    // Check IP whitelist
    let whitelist = cfg["ip_whitelist"]
        .as_array()
        .map(|a| a.iter().any(|v| v.as_str().map_or(false, |s| s == ip)))
        .unwrap_or(false);
    if whitelist {
        return Ok(Json(json!({
            "success": true,
            "data": { "verdict": "allow", "reason": "ip_whitelist" }
        })));
    }

    // Check host whitelist for the tier
    let host_listed = !host.is_empty()
        && cfg["host_whitelist"][tier]
            .as_array()
            .map(|a| a.iter().any(|v| v.as_str().map_or(false, |s| s == host)))
            .unwrap_or(false);
    if host_listed {
        let mode = cfg["tier_whitelist_mode"][tier].as_str().unwrap_or("blacklist_only");
        let verdict = if mode == "full_bypass" { "bypass" } else { "allow" };
        return Ok(Json(json!({
            "success": true,
            "data": { "verdict": verdict, "reason": "host_whitelist" }
        })));
    }

    Ok(Json(json!({
        "success": true,
        "data": { "verdict": "pass", "reason": "no_match" }
    })))
}
