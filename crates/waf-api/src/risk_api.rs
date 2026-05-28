//! Risk scoring API — GET/PUT /api/risk/config, GET /api/risk/metrics,
//! GET /api/risk/actors, POST /api/risk/actors/:id/credit|clear.
//!
//! Config source: `configs/risk.yaml`. Root key `risk:` is unwrapped before
//! sending to the frontend.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Path helper (shared pattern) ────────────────────────────────────────────

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

// ─── Mapping helpers ──────────────────────────────────────────────────────────

/// Map risk.yaml `risk:` block → FE `RiskConfig`
fn yaml_to_fe(r: &Value) -> Value {
    let decay = r.get("decay").cloned().unwrap_or(Value::Null);
    let canary = r.get("canary").cloned().unwrap_or(Value::Null);
    let store = r.get("store").cloned().unwrap_or(Value::Null);
    let seed = r.get("seed").cloned().unwrap_or(Value::Null);
    json!({
        "enabled": r.get("enabled").and_then(Value::as_bool).unwrap_or(false),
        "ttl_secs": r.get("ttl_secs").and_then(Value::as_i64).unwrap_or(1800),
        "gc_interval_secs": r.get("gc_interval_secs").and_then(Value::as_i64).unwrap_or(60),
        "header_name": r.get("header_name").and_then(Value::as_str).unwrap_or("X-WAF-Risk-Score"),
        "emit_header": r.get("emit_header").and_then(Value::as_bool).unwrap_or(true),
        "decay": {
            "min_clean_streak": decay.get("min_clean_streak").and_then(Value::as_i64).unwrap_or(10),
            "decay_rate": decay.get("decay_rate").and_then(Value::as_i64).unwrap_or(1),
            "max_decay": decay.get("max_decay").and_then(Value::as_i64).unwrap_or(50)
        },
        "canary": {
            "enabled": canary.get("enabled").and_then(Value::as_bool).unwrap_or(false),
            "paths": canary.get("paths").and_then(Value::as_array).map(|a| {
                a.iter().filter_map(Value::as_str).collect::<Vec<_>>()
            }).unwrap_or_default(),
            "ban_ttl_secs": canary.get("ban_ttl_secs").and_then(Value::as_i64).unwrap_or(3600)
        },
        "store": {
            "backend": store.get("backend").and_then(Value::as_str).unwrap_or("memory"),
            "redis": store.get("redis").cloned().unwrap_or(Value::Null)
        },
        "seed": {
            "enabled": seed.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            "tor_delta": seed.get("tor_delta").and_then(Value::as_i64).unwrap_or(30),
            "datacenter_delta": seed.get("datacenter_delta").and_then(Value::as_i64).unwrap_or(15),
            "bad_asn_delta": seed.get("bad_asn_delta").and_then(Value::as_i64).unwrap_or(25)
        }
    })
}

fn default_risk_fe() -> Value {
    json!({
        "enabled": false,
        "ttl_secs": 1800,
        "gc_interval_secs": 60,
        "header_name": "X-WAF-Risk-Score",
        "emit_header": true,
        "decay": { "min_clean_streak": 10, "decay_rate": 1, "max_decay": 50 },
        "canary": { "enabled": false, "paths": [], "ban_ttl_secs": 3600 },
        "store": { "backend": "memory" },
        "seed": { "enabled": true, "tor_delta": 30, "datacenter_delta": 15, "bad_asn_delta": 25 }
    })
}

/// FE `RiskConfig` → risk.yaml wrapped with `risk:` key
fn fe_to_yaml(body: &Value) -> Value {
    let seed = body.get("seed").cloned().unwrap_or(Value::Null);
    json!({
        "risk": {
            "schema_version": 1,
            "enabled": body.get("enabled"),
            "ttl_secs": body.get("ttl_secs"),
            "gc_interval_secs": body.get("gc_interval_secs"),
            "header_name": body.get("header_name"),
            "emit_header": body.get("emit_header"),
            "store": body.get("store"),
            "decay": body.get("decay"),
            "seed": {
                "enabled": seed.get("enabled"),
                "tor_delta": seed.get("tor_delta"),
                "datacenter_delta": seed.get("datacenter_delta"),
                "bad_asn_delta": seed.get("bad_asn_delta")
            },
            "canary": body.get("canary")
        }
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_risk_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/risk.yaml");
    let cfg = match read_yaml_opt(&path).await {
        Some(v) if v.get("risk").is_some_and(|r| !r.is_null()) => yaml_to_fe(v.get("risk").unwrap_or(&Value::Null)),
        _ => default_risk_fe(),
    };
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_risk_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/risk.yaml");
    write_yaml(&path, &fe_to_yaml(&body)).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn get_risk_metrics(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "success": true,
        "data": {
            "actor_count": 0, "avg_score": 0, "p95_score": 0,
            "scored_last_hour": 0, "blocked_last_hour": 0, "challenged_last_hour": 0
        }
    })))
}

#[derive(Deserialize)]
pub struct ActorsQuery {
    pub limit: Option<i64>,
    pub min_score: Option<i64>,
    pub page: Option<i64>,
}

pub async fn list_risk_actors(_: State<Arc<AppState>>, Query(_q): Query<ActorsQuery>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": [], "total": 0 })))
}

pub async fn credit_risk_actor(
    _: State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(_body): Json<Value>,
) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": { "id": id } })))
}

pub async fn clear_risk_actor(_: State<Arc<AppState>>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({ "success": true, "data": { "id": id } })))
}
