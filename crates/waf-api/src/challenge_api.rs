//! Challenge engine config API — GET/PUT /api/challenge/config, GET /api/challenge/stats,
//! POST /api/challenge/preview.
//!
//! Config source: `configs/challenge.yaml`. The YAML root key is `challenge:`; this layer
//! strips/adds that wrapper so the frontend receives a flat `ChallengeConfig` object.

use std::sync::Arc;

use axum::{Json, extract::State, http::header, response::IntoResponse};
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Path helper ─────────────────────────────────────────────────────────────

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

async fn read_yaml(path: &std::path::Path) -> Result<Value, ApiError> {
    tokio::fs::read_to_string(path).await.map_or_else(
        |_| Ok(Value::Null),
        |raw| serde_yaml::from_str::<Value>(&raw).map_err(|e| ApiError::BadRequest(format!("parse YAML: {e}"))),
    )
}

async fn write_yaml(path: &std::path::Path, value: &Value) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let s = serde_yaml::to_string(value).map_err(|e| ApiError::Internal(anyhow::anyhow!("yaml: {e}")))?;
    // Atomic write via temp file
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, s.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write tmp: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

// ─── Mapping helpers ──────────────────────────────────────────────────────────

/// YAML challenge.* → flat FE `ChallengeConfig`
fn yaml_to_fe(c: &Value) -> Value {
    let token = c.get("token").cloned().unwrap_or(Value::Null);
    let nonce = c.get("nonce_store").cloned().unwrap_or(Value::Null);
    json!({
        "enabled": c.get("enabled").and_then(Value::as_bool).unwrap_or(true),
        "challenge_type": c.get("type").and_then(Value::as_str).unwrap_or("js_challenge"),
        "ttl_secs": token.get("ttl_secs").and_then(Value::as_i64).unwrap_or(300),
        "cookie_name": token.get("cookie_name").and_then(Value::as_str).unwrap_or("__waf_cc"),
        "cookie_max_age": token.get("cookie_max_age").and_then(Value::as_i64).unwrap_or(300),
        "same_site": token.get("same_site").and_then(Value::as_str).unwrap_or("Strict"),
        "http_only": token.get("http_only").and_then(Value::as_bool).unwrap_or(false),
        "branding": {
            "title": c.get("branding").and_then(|b| b.get("title")).and_then(Value::as_str).unwrap_or("Security Check"),
            "message": c.get("branding").and_then(|b| b.get("message")).and_then(Value::as_str).unwrap_or("Please wait while we verify your browser...")
        },
        "nonce_store": {
            "capacity": nonce.get("capacity").and_then(Value::as_i64).unwrap_or(100_000),
            "gc_interval_secs": nonce.get("gc_interval_secs").and_then(Value::as_i64).unwrap_or(60)
        }
    })
}

/// Flat FE `ChallengeConfig` → YAML challenge.* wrapper
fn fe_to_yaml(body: &Value) -> Value {
    json!({
        "challenge": {
            "enabled": body["enabled"],
            "type": body["challenge_type"],
            "token": {
                "ttl_secs": body["ttl_secs"],
                "cookie_name": body["cookie_name"],
                "cookie_max_age": body["cookie_max_age"],
                "same_site": body["same_site"],
                "http_only": body["http_only"]
            },
            "branding": body["branding"],
            "nonce_store": body["nonce_store"]
        }
    })
}

fn default_challenge_fe() -> Value {
    json!({
        "enabled": true,
        "challenge_type": "js_challenge",
        "ttl_secs": 300,
        "cookie_name": "__waf_cc",
        "cookie_max_age": 300,
        "same_site": "Strict",
        "http_only": false,
        "branding": { "title": "Security Check", "message": "Please wait while we verify your browser..." },
        "nonce_store": { "capacity": 100_000, "gc_interval_secs": 60 }
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_challenge_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/challenge.yaml");
    let raw = read_yaml(&path).await?;
    let cfg = raw.get("challenge").map_or_else(default_challenge_fe, yaml_to_fe);
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_challenge_config(
    State(state): State<Arc<AppState>>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/challenge.yaml");
    let yaml_val = fe_to_yaml(&body);
    write_yaml(&path, &yaml_val).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn get_challenge_stats(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Ok(Json(json!({
        "success": true,
        "data": { "issued": 0, "passed": 0, "failed": 0, "replays": 0 }
    })))
}

/// Returns raw HTML (the FE calls `resp.text()` directly).
pub async fn challenge_preview(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> impl IntoResponse {
    let path = resolve_path(&state, "configs/challenge.yaml");
    let raw = read_yaml(&path).await.unwrap_or(Value::Null);
    let title = body
        .get("branding")
        .and_then(|b| b.get("title"))
        .and_then(Value::as_str)
        .or_else(|| {
            raw.get("challenge")
                .and_then(|c| c.get("branding"))
                .and_then(|b| b.get("title"))
                .and_then(Value::as_str)
        })
        .unwrap_or("Security Check")
        .to_owned();
    let message = body
        .get("branding")
        .and_then(|b| b.get("message"))
        .and_then(Value::as_str)
        .or_else(|| {
            raw.get("challenge")
                .and_then(|c| c.get("branding"))
                .and_then(|b| b.get("message"))
                .and_then(Value::as_str)
        })
        .unwrap_or("Please wait while we verify your browser...")
        .to_owned();

    let html = format!(
        r#"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{title}</title>
<style>body{{font-family:sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f5}}
.box{{background:#fff;padding:40px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,.15);text-align:center;max-width:400px}}
h1{{color:#1890ff;font-size:1.5rem}}p{{color:#555}}</style></head>
<body><div class="box"><h1>&#x1F512; {title}</h1><p>{message}</p></div></body></html>"#
    );
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html)
}
