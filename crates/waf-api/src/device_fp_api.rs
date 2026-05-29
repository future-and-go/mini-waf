//! Device fingerprinting API — GET/PUT `/api/device-fp/config`,
//! GET `/api/device-fp/recent`, GET `/api/device-fp/conflicts`.
//!
//! Config source: `configs/device-fp.yaml`. Root key `device_fp:` is
//! unwrapped before sending to the frontend. PUT routes require admin JWT
//! and are body-limited to 256 KiB by the route layer in `server.rs`.

use std::path::Path;
use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Max body size for device-fp PUT requests (256 KiB).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

// ─── Auth gate ───────────────────────────────────────────────────────────────

fn require_admin(headers: &HeaderMap, jwt_secret: &str) -> Result<Claims, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("missing bearer token".into()))?;
    validate_admin_token(token, jwt_secret).map_err(|e| ApiError::Unauthorized(e.to_string()))
}

// ─── Filesystem helpers ──────────────────────────────────────────────────────

async fn read_yaml_value(path: &Path) -> Value {
    let Ok(raw) = tokio::fs::read_to_string(path).await else {
        return Value::Null;
    };
    serde_yaml::from_str::<Value>(&raw).unwrap_or_else(|e| {
        tracing::warn!(path = %path.display(), error = %e, "device-fp: YAML parse failed; falling back to defaults");
        Value::Null
    })
}

async fn write_yaml_value(path: &Path, value: &Value) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let s = serde_yaml::to_string(value).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize: {e}")))?;
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, s.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

// ─── Provider list ↔ object mapping ──────────────────────────────────────────

/// Convert YAML providers list → FE object keyed by provider name.
/// Adds `enabled: true` for any entry that lacks it.
fn providers_to_obj(providers: &Value) -> Value {
    let Some(arr) = providers.as_array() else {
        return json!({});
    };
    let mut map = serde_json::Map::new();
    for p in arr {
        let Some(name) = p.get("name").and_then(Value::as_str) else {
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

/// Convert FE providers object → YAML array (inverse of `providers_to_obj`).
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
            "h2":  { "enabled": false, "hash": "akamai" }
        },
        "store": { "backend": "memory", "ttl_secs": 3600 },
        "providers": [
            { "name": "ip_hopping",   "window_secs": 600, "max_distinct_ips": 3,  "signal_weight": 25 },
            { "name": "fp_conflict",  "window_secs": 600, "max_distinct_uas": 3,  "signal_weight": 25 },
            { "name": "ua_entropy",   "min_entropy_x100": 250, "signal_weight": 15 },
            { "name": "ua_blocklist", "blocklist_patterns": [], "signal_weight": 30 },
            { "name": "h2_anomaly",   "signal_weight": 20 }
        ],
        "behavior": {
            "window_size":      16,
            "actor_ttl_secs":   600,
            "burst_interval":   { "enabled": true, "threshold_ms": 50, "min_consecutive": 5, "risk_delta": 15 },
            "regularity":       { "enabled": true, "min_samples": 6, "cv_threshold": 0.15, "min_mean_ms": 100, "risk_delta": 10 },
            "zero_depth":       { "enabled": true, "min_samples": 4, "critical_hits_required": 2, "risk_delta": 10 },
            "missing_referer":  {
                "enabled": true, "risk_delta": 5,
                "exempt_paths":    ["/", "/login", "/index", "/health"],
                "exempt_prefixes": ["/static/", "/assets/", "/api/"]
            }
        }
    })
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn get_device_fp_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/device-fp.yaml");
    let raw = read_yaml_value(&path).await;
    let mut cfg = match raw.get("device_fp") {
        Some(fp) if !fp.is_null() => fp.clone(),
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
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    if !body.is_object() {
        return Err(ApiError::BadRequest("device-fp body must be a JSON object".into()));
    }
    let path = resolve_under_root(&state, "configs/device-fp.yaml");
    // The FE sends providers as an object; convert back to array for YAML storage.
    let mut yaml_body = body.clone();
    if let Some(obj) = yaml_body.as_object_mut()
        && let Some(providers) = obj.get("providers").cloned()
    {
        obj.insert("providers".to_owned(), providers_to_array(&providers));
    }
    write_yaml_value(&path, &json!({ "device_fp": yaml_body })).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn list_recent_fps(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    // Recent-fingerprint store is part of the device_fp engine subsystem
    // and is not yet plumbed through AppState. Returning an empty list keeps
    // the FE shape stable until the wiring lands.
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

pub async fn list_fp_conflicts(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    // Conflict-detector state is part of the device_fp engine subsystem
    // and is not yet plumbed through AppState.
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn providers_to_obj_keys_by_name_and_inserts_enabled() {
        let arr = json!([
            { "name": "ip_hopping", "window_secs": 600 },
            { "name": "ua_entropy", "min_entropy_x100": 250, "enabled": false }
        ]);
        let obj = providers_to_obj(&arr);
        assert_eq!(obj["ip_hopping"]["enabled"], true);
        assert_eq!(obj["ua_entropy"]["enabled"], false);
        assert_eq!(obj["ip_hopping"]["window_secs"], 600);
    }

    #[test]
    fn providers_round_trip_to_array_and_back() {
        let arr = json!([
            { "name": "ip_hopping", "window_secs": 600 },
            { "name": "fp_conflict", "window_secs": 600 }
        ]);
        let obj = providers_to_obj(&arr);
        let back = providers_to_array(&obj);
        // Object iteration order is preserved by serde_json::Map (insertion order).
        let back_names: Vec<String> = back
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.get("name").and_then(Value::as_str).map(str::to_owned))
            .collect();
        assert!(back_names.contains(&"ip_hopping".to_owned()));
        assert!(back_names.contains(&"fp_conflict".to_owned()));
    }

    #[test]
    fn providers_to_obj_handles_empty() {
        let obj = providers_to_obj(&json!([]));
        assert!(obj.as_object().unwrap().is_empty());
    }

    #[test]
    fn providers_to_array_handles_empty() {
        let arr = providers_to_array(&json!({}));
        assert!(arr.as_array().unwrap().is_empty());
    }

    #[test]
    fn default_device_fp_has_known_providers() {
        let d = default_device_fp_fe();
        let names: Vec<&str> = d["providers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|p| p.get("name").and_then(Value::as_str))
            .collect();
        assert!(names.contains(&"ip_hopping"));
        assert!(names.contains(&"ua_blocklist"));
        assert!(names.contains(&"h2_anomaly"));
    }
}
