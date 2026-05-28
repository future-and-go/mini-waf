//! Geo restriction API — CRUD for country-based allow/block rules.
//!
//! Rules are persisted in `rules/geo-rules.yaml` (relative to the main config
//! directory).  The lookup endpoint returns a stub response because GeoIP xdb
//! files may not be installed in every deployment.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Path helpers ──────────────────────────────────────────────────────────────

fn rules_path(state: &AppState) -> std::path::PathBuf {
    if let Some(main) = &state.main_config_file {
        let p = std::path::Path::new(main.as_str());
        let root = p.parent().and_then(|c| c.parent()).unwrap_or(std::path::Path::new("."));
        root.join("configs/geo-rules.yaml")
    } else {
        std::path::PathBuf::from("configs/geo-rules.yaml")
    }
}

// ─── YAML helpers ─────────────────────────────────────────────────────────────

async fn read_rules(path: &std::path::Path) -> Vec<Value> {
    let Ok(raw) = tokio::fs::read_to_string(path).await else {
        return vec![];
    };
    let Ok(doc) = serde_yaml::from_str::<Value>(&raw) else {
        return vec![];
    };
    doc.get("rules").and_then(|v| v.as_array()).cloned().unwrap_or_default()
}

async fn write_rules(path: &std::path::Path, rules: &[Value]) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let doc = json!({ "rules": rules });
    let s = serde_yaml::to_string(&doc).map_err(|e| ApiError::Internal(anyhow::anyhow!("yaml serialize: {e}")))?;
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, s.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

fn next_id(rules: &[Value]) -> i64 {
    rules
        .iter()
        .filter_map(|r| r.get("id").and_then(|v| v.as_i64()))
        .max()
        .unwrap_or(0)
        + 1
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn list_geo_rules(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = rules_path(&state);
    let rules = read_rules(&path).await;
    let total = rules.len();
    Ok(Json(json!({ "success": true, "data": rules, "total": total })))
}

pub async fn create_geo_rule(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = rules_path(&state);
    let mut rules = read_rules(&path).await;

    let iso = body
        .get("iso_code")
        .and_then(|v| v.as_str())
        .unwrap_or("XX")
        .to_uppercase();

    let new_rule = json!({
        "id":           next_id(&rules),
        "iso_code":     iso,
        "country_name": body.get("country_name"),
        "action":       body.get("action").and_then(|v| v.as_str()).unwrap_or("block"),
        "scope":        body.get("scope").and_then(|v| v.as_str()).unwrap_or("global"),
        "enabled":      true,
        "created_at":   chrono::Utc::now().to_rfc3339(),
    });

    rules.push(new_rule.clone());
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true, "data": new_rule })))
}

pub async fn patch_geo_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<i64>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let path = rules_path(&state);
    let mut rules = read_rules(&path).await;

    let idx = rules
        .iter()
        .position(|r| r.get("id").and_then(|v| v.as_i64()) == Some(id))
        .ok_or_else(|| ApiError::NotFound(format!("geo rule {id} not found")))?;

    if let Some(obj) = rules[idx].as_object_mut() {
        for field in &["enabled", "action", "scope"] {
            if let Some(v) = body.get(*field) {
                obj.insert((*field).to_owned(), v.clone());
            }
        }
    }

    let updated = rules[idx].clone();
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true, "data": updated })))
}

pub async fn delete_geo_rule(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let path = rules_path(&state);
    let mut rules = read_rules(&path).await;
    let before = rules.len();
    rules.retain(|r| r.get("id").and_then(|v| v.as_i64()) != Some(id));
    if rules.len() == before {
        return Err(ApiError::NotFound(format!("geo rule {id} not found")));
    }
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true })))
}

/// POST /api/geoip/lookup — IP → country lookup.
/// Returns a stub response; GeoIP xdb database must be installed for real data.
pub async fn lookup_ip(_state: State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let ip_str = body.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_owned();

    Ok(Json(json!({
        "success": true,
        "data": {
            "ip":           ip_str,
            "iso_code":     "XX",
            "country_name": "Unknown — GeoIP database not loaded",
            "isp":          null
        }
    })))
}
