//! `DDoS` protection API — GET/PUT `/api/ddos/config`, GET `/api/ddos/metrics`,
//! GET `/api/ddos/ban-table`, DELETE `/api/ddos/ban-table/:ip`.
//!
//! Config source: `configs/ddos.yaml`. The ban-table is sourced from the live
//! `DynamicBanTable` held by `WafEngine`; mutations require the `admin` role.
//! Request bodies are capped at 256 KiB by the route layer.

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub const MAX_BODY_BYTES: usize = 256 * 1024;

// ─── Typed request/response models ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosThreshold {
    pub threshold_rps: i64,
    pub window_secs: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosStore {
    pub backend: String,
    #[serde(default)]
    pub redis_url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DdosConfigBody {
    pub enabled: bool,
    pub per_ip: DdosThreshold,
    pub per_fingerprint: DdosThreshold,
    pub ban_durations_secs: Vec<i64>,
    pub store: DdosStore,
}

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

async fn read_yaml_opt(path: &Path) -> Option<DdosConfigBody> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    match serde_yaml::from_str::<DdosConfigBody>(&raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "ddos: YAML parse failed; falling back to defaults");
            None
        }
    }
}

async fn write_yaml(path: &Path, value: &DdosConfigBody) -> Result<(), ApiError> {
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

fn default_ddos_config() -> DdosConfigBody {
    DdosConfigBody {
        enabled: true,
        per_ip: DdosThreshold {
            threshold_rps: 100,
            window_secs: 10,
        },
        per_fingerprint: DdosThreshold {
            threshold_rps: 200,
            window_secs: 10,
        },
        ban_durations_secs: vec![60, 300, 3600],
        store: DdosStore {
            backend: "memory".to_string(),
            redis_url: String::new(),
        },
    }
}

#[inline]
fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn get_ddos_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/ddos.yaml");
    let cfg = read_yaml_opt(&path).await.unwrap_or_else(default_ddos_config);
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_ddos_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<DdosConfigBody>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;

    if body.ban_durations_secs.is_empty() {
        return Err(ApiError::BadRequest("ban_durations_secs must not be empty".into()));
    }
    if body.ban_durations_secs.iter().any(|d| *d <= 0) {
        return Err(ApiError::BadRequest(
            "ban_durations_secs entries must be positive".into(),
        ));
    }
    if body.per_ip.threshold_rps <= 0 || body.per_fingerprint.threshold_rps <= 0 {
        return Err(ApiError::BadRequest("threshold_rps must be positive".into()));
    }
    if body.per_ip.window_secs <= 0 || body.per_fingerprint.window_secs <= 0 {
        return Err(ApiError::BadRequest("window_secs must be positive".into()));
    }

    let path = resolve_under_root(&state, "configs/ddos.yaml");
    write_yaml(&path, &body).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn get_ddos_metrics(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let snap = state.engine.ddos_metrics().snapshot();
    Ok(Json(json!({
        "success": true,
        "data": {
            "active_bans": snap.bans_active,
            "bursts_total": snap.burst_total,
            "bursts_per_ip": snap.burst_per_ip,
            "bursts_per_fp": snap.burst_per_fp,
            "bursts_per_tier": snap.burst_per_tier,
            "bans_total": snap.bans_total,
            "store_errors": snap.store_errors,
            "degrade_events": snap.degrade_events
        }
    })))
}

pub async fn list_ban_table(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let now_ms = now_epoch_ms();
    let mut entries: Vec<Value> = state
        .engine
        .ddos_ban_table()
        .snapshot()
        .into_iter()
        .filter(|(_, exp)| *exp > now_ms)
        .map(|(ip, exp)| {
            json!({
                "ip": ip.to_string(),
                "expires_at_ms": exp,
                "ttl_remaining_secs": ((exp - now_ms) / 1000).max(0),
            })
        })
        .collect();
    entries.sort_by(|a, b| {
        a.get("ip")
            .and_then(Value::as_str)
            .unwrap_or("")
            .cmp(b.get("ip").and_then(Value::as_str).unwrap_or(""))
    });
    let total = entries.len();
    Ok(Json(json!({ "success": true, "data": entries, "total": total })))
}

pub async fn delete_ban_entry(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(ip): AxumPath<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;

    let parsed: std::net::IpAddr = ip
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid IP address: {ip}")))?;

    let removed = state.engine.ddos_ban_table().remove(&parsed);
    tracing::info!(ip = %parsed, removed, "ddos: manual unban");
    Ok(Json(json!({
        "success": true,
        "data": { "ip": parsed.to_string(), "removed": removed }
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips_yaml() {
        let cfg = default_ddos_config();
        let s = serde_yaml::to_string(&cfg).unwrap();
        let back: DdosConfigBody = serde_yaml::from_str(&s).unwrap();
        assert_eq!(back.ban_durations_secs, cfg.ban_durations_secs);
        assert_eq!(back.store.backend, "memory");
    }

    #[test]
    fn empty_ban_durations_rejected() {
        let mut cfg = default_ddos_config();
        cfg.ban_durations_secs.clear();
        assert!(cfg.ban_durations_secs.is_empty());
    }
}
