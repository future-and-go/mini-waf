//! Geo restriction API — CRUD for country-based allow/block rules.
//!
//! Rules are persisted in `configs/geo-rules.yaml` (relative to the main
//! config directory); the engine watches the same file, so CRUD hot-reloads
//! enforcement. The lookup endpoint reads the engine's `GeoIpService` and
//! falls back to a stub response when the xdb databases are not installed.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
};
use serde_json::{Value, json};

use crate::config_files::{read_yaml_opt, resolve_path, write_yaml};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── YAML helpers ─────────────────────────────────────────────────────────────

async fn read_rules(path: &std::path::Path) -> Vec<Value> {
    read_yaml_opt(path)
        .await
        .and_then(|doc| doc.get("rules").and_then(|v| v.as_array()).cloned())
        .unwrap_or_default()
}

async fn write_rules(path: &std::path::Path, rules: &[Value]) -> Result<(), ApiError> {
    write_yaml(path, &json!({ "rules": rules })).await
}

fn next_id(rules: &[Value]) -> i64 {
    rules
        .iter()
        .filter_map(|r| r.get("id").and_then(Value::as_i64))
        .max()
        .unwrap_or(0)
        + 1
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn list_geo_rules(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/geo-rules.yaml");
    let rules = read_rules(&path).await;
    let total = rules.len();
    Ok(Json(json!({ "success": true, "data": rules, "total": total })))
}

pub async fn create_geo_rule(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/geo-rules.yaml");
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
        "fail_closed":  body.get("fail_closed").and_then(Value::as_bool).unwrap_or(false),
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
    let path = resolve_path(&state, "configs/geo-rules.yaml");
    let mut rules = read_rules(&path).await;

    let idx = rules
        .iter()
        .position(|r| r.get("id").and_then(Value::as_i64) == Some(id))
        .ok_or_else(|| ApiError::NotFound(format!("geo rule {id} not found")))?;

    if let Some(obj) = rules.get_mut(idx).and_then(Value::as_object_mut) {
        for field in &["enabled", "action", "scope", "fail_closed"] {
            if let Some(v) = body.get(*field) {
                obj.insert((*field).to_owned(), v.clone());
            }
        }
    }

    let updated = rules.get(idx).cloned().unwrap_or(Value::Null);
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true, "data": updated })))
}

pub async fn delete_geo_rule(State(state): State<Arc<AppState>>, Path(id): Path<i64>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/geo-rules.yaml");
    let mut rules = read_rules(&path).await;
    let before = rules.len();
    rules.retain(|r| r.get("id").and_then(Value::as_i64) != Some(id));
    if rules.len() == before {
        return Err(ApiError::NotFound(format!("geo rule {id} not found")));
    }
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true })))
}

/// POST /api/geoip/lookup — IP → country lookup through the engine's
/// `GeoIpService`. Falls back to the stub envelope when the service is
/// disabled or the address has no xdb data (private IP / miss).
pub async fn lookup_ip(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let ip_str = body.get("ip").and_then(|v| v.as_str()).unwrap_or("").to_owned();
    let Ok(ip) = ip_str.parse::<std::net::IpAddr>() else {
        return Err(ApiError::BadRequest(format!("invalid ip: {ip_str}")));
    };

    match state.engine.geoip_lookup(ip) {
        Some(info) if !info.iso_code.is_empty() || !info.country.is_empty() => Ok(Json(json!({
            "success": true,
            "data": {
                "ip":           ip_str,
                "iso_code":     info.iso_code,
                "country_name": info.country,
                "isp":          if info.isp.is_empty() { Value::Null } else { json!(info.isp) },
            }
        }))),
        _ => Ok(Json(json!({
            "success": true,
            "data": {
                "ip":           ip_str,
                "iso_code":     "XX",
                "country_name": "Unknown — GeoIP database not loaded",
                "isp":          null
            }
        }))),
    }
}
