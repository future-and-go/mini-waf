//! Device fingerprinting API — GET/PUT /api/device-fp/config,
//! GET /api/device-fp/recent, GET /api/device-fp/conflicts.
//!
//! Config source: `configs/device-fp.yaml`. Root key `device_fp:` is
//! unwrapped before sending to the frontend.

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

/// Convert YAML providers list → FE object keyed by provider name.
/// Adds `enabled: true` for any entry that lacks it.
fn providers_to_obj(providers: &Value) -> Value {
    let Some(arr) = providers.as_array() else {
        return json!({});
    };
    let mut map = serde_json::Map::new();
    for p in arr {
        let Some(name) = p.get("name").and_then(|v| v.as_str()) else {
            continue;
        };
        let mut entry = p.clone();
        if let Some(obj) = entry.as_object_mut() {
            obj.remove("name");
            obj.entry("enabled").or_insert(Value::Bool(true));
        }
        map.insert(name.to_owned(), entry);
    }
    Value::Object(map)
}

/// Convert FE providers object → YAML array (invert of `providers_to_obj`).
fn providers_to_array(providers: &Value) -> Value {
    let Some(obj) = providers.as_object() else {
        return json!([]);
    };
    let arr: Vec<Value> = obj
        .iter()
        .map(|(name, v)| {
            let mut entry = v.clone();
            if let Some(m) = entry.as_object_mut() {
                m.insert("name".to_owned(), Value::String(name.clone()));
            }
            entry
        })
        .collect();
    Value::Array(arr)
}

fn default_device_fp_fe() -> Value {
    json!({
        "enabled": false,
        "capture": {
            "tls": { "enabled": false, "algorithms": ["ja3", "ja4"] },
            "h2": { "enabled": false, "hash": "akamai" }
        },
        "store": { "backend": "memory", "ttl_secs": 3600 },
        "providers": [
            { "name": "ip_hopping", "window_secs": 600, "max_distinct_ips": 3, "signal_weight": 25 },
            { "name": "fp_conflict", "window_secs": 600, "max_distinct_uas": 3, "signal_weight": 25 },
            { "name": "ua_entropy", "min_entropy_x100": 250, "signal_weight": 15 },
            { "name": "ua_blocklist", "blocklist_patterns": [], "signal_weight": 30 },
            { "name": "h2_anomaly", "signal_weight": 20 }
        ],
        "behavior": {
            "window_size": 16,
            "actor_ttl_secs": 600,
            "burst_interval": { "enabled": true, "threshold_ms": 50, "min_consecutive": 5, "risk_delta": 15 },
            "regularity": { "enabled": true, "min_samples": 6, "cv_threshold": 0.15, "min_mean_ms": 100, "risk_delta": 10 },
            "zero_depth": { "enabled": true, "min_samples": 4, "critical_hits_required": 2, "risk_delta": 10 },
            "missing_referer": {
                "enabled": true, "risk_delta": 5,
                "exempt_paths": ["/", "/login", "/index", "/health"],
                "exempt_prefixes": ["/static/", "/assets/", "/api/"]
            }
        }
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_device_fp_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/device-fp.yaml");
    let mut cfg = match read_yaml_opt(&path).await {
        Some(v) if v.get("device_fp").is_some_and(|fp| !fp.is_null()) => {
            v.get("device_fp").cloned().unwrap_or(Value::Null)
        }
        _ => default_device_fp_fe(),
    };
    // YAML stores providers as an array; the FE form expects an object keyed by name.
    if let Some(obj) = cfg.as_object_mut()
        && let Some(providers) = obj.get("providers").cloned()
    {
        obj.insert("providers".to_owned(), providers_to_obj(&providers));
    }
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_device_fp_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/device-fp.yaml");
    // The FE sends providers as an object; convert back to array for YAML storage.
    let mut yaml_body = body.clone();
    if let Some(obj) = yaml_body.as_object_mut()
        && let Some(providers) = obj.get("providers").cloned()
    {
        obj.insert("providers".to_owned(), providers_to_array(&providers));
    }
    write_yaml(&path, &json!({ "device_fp": yaml_body })).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn list_recent_fps(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

pub async fn list_fp_conflicts(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}
