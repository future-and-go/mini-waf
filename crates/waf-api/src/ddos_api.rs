//! `DDoS` protection API — GET/PUT /api/ddos/config, GET /api/ddos/metrics,
//! GET /api/ddos/ban-table, DELETE /api/ddos/ban-table/:ip.
//!
//! Config source: `configs/ddos.yaml`. Ban-table is in-memory only (no persistence yet).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json,
    extract::{Path, State, connect_info::ConnectInfo},
    http::{HeaderMap, header::AUTHORIZATION},
};
use serde_json::{Value, json};

use waf_engine::checks::ddos::config::{DdosDocument, DdosFileConfig};

use crate::auth::validate_access_token;
use crate::config_files::{resolve_path, write_yaml_str};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Current wall-clock epoch milliseconds.
fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Best-effort admin username from the bearer token for audit attribution.
/// `require_auth` already validated the token; a miss just yields `None`.
fn bearer_username(headers: &HeaderMap, secret: &str) -> Option<String> {
    let token = headers.get(AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    validate_access_token(token, secret).ok().map(|c| c.sub)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_ddos_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/ddos.yaml");
    let doc = match tokio::fs::read_to_string(&path).await {
        Ok(raw) => serde_yaml::from_str::<DdosDocument>(&raw)
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("parse ddos config: {e}")))?,
        Err(_) => DdosDocument::default(),
    };
    let data = serde_json::to_value(&doc.ddos)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize ddos config: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

pub async fn put_ddos_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let cfg: DdosFileConfig =
        serde_json::from_value(body).map_err(|e| ApiError::BadRequest(format!("invalid ddos config: {e}")))?;
    cfg.validate()
        .map_err(|e| ApiError::BadRequest(format!("ddos config validation: {e}")))?;
    let doc = DdosDocument { ddos: cfg };
    let path = resolve_path(&state, "configs/ddos.yaml");
    let yaml_str =
        serde_yaml::to_string(&doc).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize yaml: {e}")))?;
    write_yaml_str(&path, &yaml_str).await?;
    let data =
        serde_json::to_value(&doc.ddos).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize response: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data })))
}

/// `GET /api/ddos/metrics` — live `DDoS` counters (B1a).
///
/// `active_bans` is the **live** ban-table size after pruning expired entries
/// (more honest than the drifting `bans_active` metric). `bursts_1h` /
/// `bans_issued_1h` are **lifetime** totals from the engine (the engine keeps
/// no 1-hour window; the FE cards are labeled "(total)").
pub async fn get_ddos_metrics(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let metrics = state.engine.ddos_metrics();
    let ban_table = state.engine.ddos_ban_table();
    // Purge expired bans and keep `bans_active` in sync — the counter is
    // incremented on ban but otherwise never decremented, so wiring the
    // decrement into the purge path stops it drifting upward (plan B1 §8).
    let purged = ban_table.purge_expired(now_epoch_ms());
    if purged > 0 {
        metrics.dec_bans_active(u64::try_from(purged).unwrap_or(u64::MAX));
    }

    Ok(Json(json!({
        "success": true,
        "data": {
            "active_bans": ban_table.len(),
            "bursts_1h": metrics.burst_total(),
            "bans_issued_1h": metrics.bans_total(),
            "store_errors": metrics.store_errors(),
        }
    })))
}

/// `GET /api/ddos/ban-table` — enumerate the live (non-expired) bans (B1b).
pub async fn list_ban_table(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let now = now_epoch_ms();
    let rows: Vec<Value> = state
        .engine
        .ddos_ban_table()
        .snapshot(now)
        .into_iter()
        .map(|r| {
            json!({
                "ip": r.ip.to_string(),
                "banned_until_ms": r.expires_ms,
                "ban_level": r.ban_level,
                "last_rps": r.last_rps,
                "reason": r.reason,
            })
        })
        .collect();
    let total = rows.len();
    Ok(Json(json!({ "success": true, "data": rows, "total": total })))
}

/// `DELETE /api/ddos/ban-table/{ip}` — manually unban an IP (B1c).
///
/// Idempotent: removing an absent/expired IP still returns `200`. The mutation
/// is audited (`action="ddos.unban"`).
pub async fn delete_ban_entry(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(ip_str): Path<String>,
) -> ApiResult<Json<Value>> {
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid IP address: {ip_str}")))?;

    let removed = state.engine.ddos_ban_table().remove(ip);
    if removed {
        // Keep `bans_active` honest on the manual-unban exit path too.
        state.engine.ddos_metrics().dec_bans_active(1);
    }

    let admin_username = bearer_username(&headers, &state.jwt_secret);
    tracing::info!(action = "ddos.unban", ip = %ip, removed, admin = ?admin_username, "manual DDoS unban");
    if let Err(e) = state
        .db
        .create_audit_log(
            admin_username.as_deref(),
            "ddos.unban",
            Some("ddos_ban"),
            Some(&ip.to_string()),
            Some(json!({ "removed": removed })),
            Some(&peer.ip().to_string()),
        )
        .await
    {
        tracing::warn!("failed to write audit log for ddos unban: {e}");
    }

    Ok(Json(json!({ "success": true, "data": { "ip": ip.to_string() } })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The admin-panel `DDoS` page PUTs the `DdosFileConfig` shape verbatim,
    /// sending `null` for unprotected tiers and for a disabled redis block.
    /// That exact payload must deserialize, validate, and — once written as
    /// YAML — reparse through the engine parser the hot-reload watcher uses.
    #[test]
    fn admin_panel_put_payload_round_trips() {
        let body = json!({
            "schema_version": 1,
            "enabled": true,
            "hot_reload": true,
            "gc_interval_s": 60,
            "max_keys": 100_000,
            "tiers": {
                "critical": {
                    "per_fp_threshold": 50,
                    "per_fp_window_s": 10,
                    "per_tier_threshold": 500,
                    "per_tier_window_s": 10
                },
                "high": null,
                "medium": null,
                "catch_all": null
            },
            "redis": null
        });
        let cfg: DdosFileConfig = serde_json::from_value(body).expect("FE payload must deserialize");
        cfg.validate().expect("FE payload must validate");

        let doc = DdosDocument { ddos: cfg };
        let yaml = serde_yaml::to_string(&doc).expect("serialize yaml");
        DdosFileConfig::from_yaml_str(&yaml).expect("saved YAML must reparse through engine parser");
    }

    /// Variant with the redis block enabled in the form.
    #[test]
    fn admin_panel_redis_payload_accepted() {
        let body = json!({
            "schema_version": 1,
            "enabled": false,
            "hot_reload": true,
            "gc_interval_s": 60,
            "max_keys": 100_000,
            "tiers": { "critical": null, "high": null, "medium": null, "catch_all": null },
            "redis": { "url": "redis://127.0.0.1:6379", "key_prefix": "wafddos:", "op_timeout_ms": 50 }
        });
        let cfg: DdosFileConfig = serde_json::from_value(body).expect("deserialize");
        cfg.validate().expect("validate");
    }
}
