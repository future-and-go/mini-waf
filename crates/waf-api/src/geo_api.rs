//! Geo restriction API — CRUD for country-based allow/block rules + IP lookup.
//!
//! Rules are persisted in `configs/geo-rules.yaml` (relative to the main
//! config directory — matches the established `configs/<feature>.yaml` split).
//! New rules use UUID identifiers so two concurrent POSTs cannot collide.
//! PUT/PATCH/DELETE routes require an admin JWT.

use std::path::Path;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Max body size for geo PUT/PATCH requests (256 KiB).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

/// Allow-listed PATCH keys. Anything outside this set is rejected with 400
/// so accidental client payload drift cannot silently overwrite fields the
/// API never intended to expose for partial updates.
const PATCHABLE_FIELDS: &[&str] = &["enabled", "action", "scope"];

const VALID_ACTIONS: &[&str] = &["block", "allow", "challenge"];
const VALID_SCOPES: &[&str] = &["global", "per_host"];

// ─── Typed request models ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoRule {
    pub id: String,
    pub iso_code: String,
    #[serde(default)]
    pub country_name: Option<String>,
    pub action: String,
    pub scope: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub iso_code: String,
    #[serde(default)]
    pub country_name: Option<String>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LookupRequest {
    pub ip: String,
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

fn rules_path(state: &AppState) -> std::path::PathBuf {
    resolve_under_root(state, "configs/geo-rules.yaml")
}

async fn read_rules(path: &Path) -> Vec<GeoRule> {
    let Ok(raw) = tokio::fs::read_to_string(path).await else {
        return Vec::new();
    };
    let doc: Value = match serde_yaml::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "geo: YAML parse failed; treating as empty");
            return Vec::new();
        }
    };
    let Some(arr) = doc.get("rules").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|v| serde_json::from_value::<GeoRule>(v.clone()).ok())
        .collect()
}

async fn write_rules(path: &Path, rules: &[GeoRule]) -> Result<(), ApiError> {
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

fn validate_action(action: &str) -> Result<(), ApiError> {
    if VALID_ACTIONS.contains(&action) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "action must be one of {VALID_ACTIONS:?}; got {action:?}"
        )))
    }
}

fn validate_scope(scope: &str) -> Result<(), ApiError> {
    if VALID_SCOPES.contains(&scope) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "scope must be one of {VALID_SCOPES:?}; got {scope:?}"
        )))
    }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn list_geo_rules(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = rules_path(&state);
    let rules = read_rules(&path).await;
    let total = rules.len();
    Ok(Json(json!({ "success": true, "data": rules, "total": total })))
}

pub async fn create_geo_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateRuleRequest>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    let action = body.action.unwrap_or_else(|| "block".to_owned());
    let scope = body.scope.unwrap_or_else(|| "global".to_owned());
    validate_action(&action)?;
    validate_scope(&scope)?;
    if body.iso_code.is_empty() || body.iso_code.len() > 8 {
        return Err(ApiError::BadRequest("iso_code must be 1-8 chars".into()));
    }

    let path = rules_path(&state);
    let mut rules = read_rules(&path).await;

    let new_rule = GeoRule {
        id: Uuid::new_v4().to_string(),
        iso_code: body.iso_code.to_uppercase(),
        country_name: body.country_name,
        action,
        scope,
        enabled: true,
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    rules.push(new_rule.clone());
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true, "data": new_rule })))
}

pub async fn patch_geo_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;

    // Reject unknown PATCH keys — accidental drift between FE and BE should
    // surface as a 400 rather than silently no-op.
    let obj = body
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("PATCH body must be a JSON object".into()))?;
    for key in obj.keys() {
        if !PATCHABLE_FIELDS.contains(&key.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "unknown PATCH key {key:?}; allowed: {PATCHABLE_FIELDS:?}"
            )));
        }
    }
    if let Some(action) = obj.get("action").and_then(Value::as_str) {
        validate_action(action)?;
    }
    if let Some(scope) = obj.get("scope").and_then(Value::as_str) {
        validate_scope(scope)?;
    }

    let path = rules_path(&state);
    let mut rules = read_rules(&path).await;

    let idx = rules
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| ApiError::NotFound(format!("geo rule {id} not found")))?;

    let Some(rule) = rules.get_mut(idx) else {
        return Err(ApiError::NotFound(format!("geo rule {id} not found")));
    };
    if let Some(v) = obj.get("enabled").and_then(Value::as_bool) {
        rule.enabled = v;
    }
    if let Some(v) = obj.get("action").and_then(Value::as_str) {
        rule.action = v.to_owned();
    }
    if let Some(v) = obj.get("scope").and_then(Value::as_str) {
        rule.scope = v.to_owned();
    }

    let updated = rule.clone();
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true, "data": updated })))
}

pub async fn delete_geo_rule(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    let path = rules_path(&state);
    let mut rules = read_rules(&path).await;
    let before = rules.len();
    rules.retain(|r| r.id != id);
    if rules.len() == before {
        return Err(ApiError::NotFound(format!("geo rule {id} not found")));
    }
    write_rules(&path, &rules).await?;
    Ok(Json(json!({ "success": true })))
}

/// POST `/api/geoip/lookup` — IP → country lookup. Returns 503 when the
/// `GeoIP` xdb database is not loaded so callers can distinguish
/// "unavailable" from "unknown country".
pub async fn lookup_ip(State(_state): State<Arc<AppState>>, Json(body): Json<LookupRequest>) -> impl IntoResponse {
    // M5: the GeoIP database accessor on `WafEngine` is not currently
    // exposed (lookup wiring lands with PR-β2 risk-scoring). Until that
    // PR lands the honest response is `503 geoip_unavailable` — the FE
    // already special-cases this status to show the right banner.
    let status = StatusCode::SERVICE_UNAVAILABLE;
    let payload = Json(json!({
        "success": false,
        "status": "geoip_unavailable",
        "data": {
            "ip":           body.ip,
            "iso_code":     null,
            "country_name": null,
            "isp":          null
        }
    }));
    (status, payload)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_action_accepts_known_actions() {
        for a in VALID_ACTIONS {
            assert!(validate_action(a).is_ok());
        }
    }

    #[test]
    fn validate_action_rejects_unknown() {
        assert!(validate_action("nuke").is_err());
    }

    #[test]
    fn validate_scope_accepts_known_scopes() {
        for s in VALID_SCOPES {
            assert!(validate_scope(s).is_ok());
        }
    }

    #[test]
    fn validate_scope_rejects_unknown() {
        assert!(validate_scope("multitenant").is_err());
    }

    #[test]
    fn patchable_fields_are_a_closed_set() {
        // Guards against accidental field expansion without an explicit
        // review — any new PATCHABLE key must be allowed here AND validated
        // in `patch_geo_rule`.
        assert_eq!(PATCHABLE_FIELDS, &["enabled", "action", "scope"]);
    }
}
