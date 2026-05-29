//! Access lists API — GET/PUT `/api/access-lists`, GET `/api/access-lists/test`.
//!
//! Config source: `configs/access-lists.yaml`. PUT validates the body with a
//! typed serde schema and requires the `admin` role. Body size is capped at
//! 256 KiB by the route layer. After a successful write the engine rule cache
//! is refreshed so live traffic sees the new lists immediately.

use std::path::Path;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::HeaderMap,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

pub const MAX_BODY_BYTES: usize = 256 * 1024;

// ─── Typed request models ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HostWhitelist {
    #[serde(default)]
    pub critical: Vec<String>,
    #[serde(default)]
    pub high: Vec<String>,
    #[serde(default)]
    pub medium: Vec<String>,
    #[serde(default)]
    pub catch_all: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierWhitelistMode {
    pub critical: String,
    pub high: String,
    pub medium: String,
    pub catch_all: String,
}

impl Default for TierWhitelistMode {
    fn default() -> Self {
        Self {
            critical: "blacklist_only".to_string(),
            high: "blacklist_only".to_string(),
            medium: "full_bypass".to_string(),
            catch_all: "full_bypass".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessConfig {
    #[serde(default = "default_version")]
    pub version: i64,
    #[serde(default)]
    pub dry_run: bool,
    #[serde(default)]
    pub ip_whitelist: Vec<String>,
    #[serde(default)]
    pub ip_blacklist: Vec<String>,
    #[serde(default)]
    pub host_whitelist: HostWhitelist,
    #[serde(default)]
    pub tier_whitelist_mode: TierWhitelistMode,
}

const fn default_version() -> i64 {
    1
}

impl Default for AccessConfig {
    fn default() -> Self {
        Self {
            version: 1,
            dry_run: false,
            ip_whitelist: Vec::new(),
            ip_blacklist: Vec::new(),
            host_whitelist: HostWhitelist::default(),
            tier_whitelist_mode: TierWhitelistMode::default(),
        }
    }
}

#[derive(Deserialize)]
pub struct TestQuery {
    pub ip: Option<String>,
    pub host: Option<String>,
    pub tier: Option<String>,
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

async fn read_yaml_opt(path: &Path) -> Option<AccessConfig> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    match serde_yaml::from_str::<AccessConfig>(&raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "access-lists: YAML parse failed; falling back to defaults");
            None
        }
    }
}

async fn write_yaml(path: &Path, value: &AccessConfig) -> Result<(), ApiError> {
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

fn validate(cfg: &AccessConfig) -> Result<(), ApiError> {
    for mode in [
        &cfg.tier_whitelist_mode.critical,
        &cfg.tier_whitelist_mode.high,
        &cfg.tier_whitelist_mode.medium,
        &cfg.tier_whitelist_mode.catch_all,
    ] {
        match mode.as_str() {
            "blacklist_only" | "full_bypass" => {}
            other => {
                return Err(ApiError::BadRequest(format!(
                    "invalid tier_whitelist_mode value: {other} (expected blacklist_only|full_bypass)"
                )));
            }
        }
    }
    Ok(())
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn get_access_lists(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/access-lists.yaml");
    let cfg = read_yaml_opt(&path).await.unwrap_or_default();
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_access_lists(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<AccessConfig>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    validate(&body)?;

    let path = resolve_under_root(&state, "configs/access-lists.yaml");
    write_yaml(&path, &body).await?;

    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!(error = %e, "access-lists: engine reload failed");
    }

    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn test_access_lists(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TestQuery>,
) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/access-lists.yaml");
    let cfg = read_yaml_opt(&path).await.unwrap_or_default();

    let ip = q.ip.as_deref().unwrap_or("");
    let host = q.host.as_deref().unwrap_or("");
    let tier = q.tier.as_deref().unwrap_or("catch_all");

    if cfg.ip_blacklist.iter().any(|v| v == ip) {
        return Ok(Json(json!({
            "success": true,
            "data": { "verdict": "block", "reason": "ip_blacklist" }
        })));
    }
    if cfg.ip_whitelist.iter().any(|v| v == ip) {
        return Ok(Json(json!({
            "success": true,
            "data": { "verdict": "allow", "reason": "ip_whitelist" }
        })));
    }

    let (hosts, mode) = match tier {
        "critical" => (&cfg.host_whitelist.critical, &cfg.tier_whitelist_mode.critical),
        "high" => (&cfg.host_whitelist.high, &cfg.tier_whitelist_mode.high),
        "medium" => (&cfg.host_whitelist.medium, &cfg.tier_whitelist_mode.medium),
        _ => (&cfg.host_whitelist.catch_all, &cfg.tier_whitelist_mode.catch_all),
    };
    if !host.is_empty() && hosts.iter().any(|v| v == host) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_round_trips_yaml() {
        let cfg = AccessConfig::default();
        let s = serde_yaml::to_string(&cfg).unwrap();
        let back: AccessConfig = serde_yaml::from_str(&s).unwrap();
        assert_eq!(back.version, 1);
        assert!(!back.dry_run);
        assert_eq!(back.tier_whitelist_mode.critical, "blacklist_only");
        assert_eq!(back.tier_whitelist_mode.medium, "full_bypass");
    }

    #[test]
    fn validate_accepts_known_modes() {
        let cfg = AccessConfig::default();
        validate(&cfg).unwrap();
    }

    #[test]
    fn validate_rejects_unknown_mode() {
        let mut cfg = AccessConfig::default();
        cfg.tier_whitelist_mode.high = "block_everything".to_string();
        let err = validate(&cfg).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }
}
