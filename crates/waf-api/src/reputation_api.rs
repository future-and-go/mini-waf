//! IP reputation editor API — FR-042 / #60.6.
//!
//! Operator-curated allow/block list with score, provenance and expiry.
//! Storage lives in `reputation_list` (migration 0018); the API boundary
//! validates `ip` via `IpAddr::parse`, clamps `score` to ±100, and rejects
//! `expires_at` values in the past. PUT/POST/DELETE require an admin JWT.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
    http::HeaderMap,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;
use waf_storage::models::{CreateReputationEntry, ReputationQuery, UpdateReputationEntry};

/// Max body size for reputation POST/PUT requests (64 KiB).
pub const MAX_BODY_BYTES: usize = 64 * 1024;

const VALID_SOURCES: &[&str] = &["manual", "crowdsec", "community", "feed"];
const MIN_SCORE: i32 = -100;
const MAX_SCORE: i32 = 100;
/// Hard cap on the per-request page size so a misbehaving client cannot
/// drain the whole list in one shot.
const MAX_LIMIT: i64 = 500;

// ─── Typed request models ────────────────────────────────────────────────────
#[derive(Debug, Deserialize)]
pub struct CreateRequest {
    pub ip: String,
    pub score: i32,
    pub source: String,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct UpdateRequest {
    pub score: Option<i32>,
    pub source: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub notes: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct ListQuery {
    pub ip_prefix: Option<String>,
    pub source: Option<String>,
    pub min_score: Option<i32>,
    pub max_score: Option<i32>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
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

// ─── Validation helpers ──────────────────────────────────────────────────────

fn validate_ip(ip: &str) -> Result<IpAddr, ApiError> {
    let parsed = IpAddr::from_str(ip).map_err(|e| ApiError::BadRequest(format!("ip parse: {e}")))?;
    if parsed.is_unspecified() {
        return Err(ApiError::BadRequest("ip must not be the unspecified address".into()));
    }
    Ok(parsed)
}

fn validate_source(source: &str) -> Result<(), ApiError> {
    if VALID_SOURCES.contains(&source) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "source must be one of {VALID_SOURCES:?}; got {source:?}"
        )))
    }
}

fn validate_score(score: i32) -> Result<(), ApiError> {
    if (MIN_SCORE..=MAX_SCORE).contains(&score) {
        Ok(())
    } else {
        Err(ApiError::BadRequest(format!(
            "score must be in [{MIN_SCORE}, {MAX_SCORE}]; got {score}"
        )))
    }
}

fn validate_expiry(expires_at: DateTime<Utc>) -> Result<(), ApiError> {
    if expires_at <= Utc::now() {
        return Err(ApiError::BadRequest("expires_at must be in the future".into()));
    }
    Ok(())
}

fn clamp_limit_value(limit: i64) -> i64 {
    limit.clamp(1, MAX_LIMIT)
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn list_reputation(State(state): State<Arc<AppState>>, Query(q): Query<ListQuery>) -> ApiResult<Json<Value>> {
    let query = ReputationQuery {
        ip_prefix: q.ip_prefix,
        source: q.source,
        min_score: q.min_score,
        max_score: q.max_score,
        limit: q.limit.map(clamp_limit_value),
        offset: q.offset.filter(|o| *o >= 0),
    };
    let (data, total) = state
        .db
        .list_reputation_entries(&query)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("list_reputation_entries: {e}")))?;
    Ok(Json(json!({ "success": true, "data": data, "total": total })))
}

pub async fn upsert_reputation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<CreateRequest>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    let _ = validate_ip(&body.ip)?;
    validate_source(&body.source)?;
    validate_score(body.score)?;
    validate_expiry(body.expires_at)?;

    let req = CreateReputationEntry {
        ip: body.ip,
        score: body.score,
        source: body.source,
        expires_at: body.expires_at,
        notes: body.notes,
    };
    let row = state
        .db
        .upsert_reputation_entry(&req)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("upsert_reputation_entry: {e}")))?;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn update_reputation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
    Json(body): Json<UpdateRequest>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    body.score.map(validate_score).transpose()?;
    body.source.as_deref().map(validate_source).transpose()?;
    body.expires_at.map(validate_expiry).transpose()?;
    let req = UpdateReputationEntry {
        score: body.score,
        source: body.source.as_deref(),
        expires_at: body.expires_at,
        notes: body.notes.as_deref(),
    };
    let row = state
        .db
        .update_reputation_entry(id, &req)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("update_reputation_entry: {e}")))?
        .ok_or_else(|| ApiError::NotFound(format!("reputation entry {id} not found")))?;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_reputation(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    let removed = state
        .db
        .delete_reputation_entry(id)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("delete_reputation_entry: {e}")))?;
    if removed {
        Ok(Json(json!({ "success": true })))
    } else {
        Err(ApiError::NotFound(format!("reputation entry {id} not found")))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn validate_ip_accepts_specified_addresses_only() {
        for ok in ["1.2.3.4", "2001:db8::1"] {
            assert!(validate_ip(ok).is_ok(), "{ok} should accept");
        }
        for err in ["0.0.0.0", "::", "not-an-ip", ""] {
            assert!(validate_ip(err).is_err(), "{err} should reject");
        }
    }

    #[test]
    fn validate_source_round_trip() {
        for s in VALID_SOURCES {
            assert!(validate_source(s).is_ok());
        }
        assert!(validate_source("nonsense").is_err());
    }

    #[test]
    fn validate_score_boundary() {
        assert!(validate_score(MIN_SCORE).is_ok());
        assert!(validate_score(MAX_SCORE).is_ok());
        assert!(validate_score(MIN_SCORE - 1).is_err());
        assert!(validate_score(MAX_SCORE + 1).is_err());
    }

    #[test]
    fn validate_expiry_rejects_past() {
        assert!(validate_expiry(Utc::now() - chrono::Duration::hours(1)).is_err());
        assert!(validate_expiry(Utc::now() + chrono::Duration::hours(1)).is_ok());
    }

    #[test]
    fn clamp_limit_value_caps_at_max() {
        assert_eq!(clamp_limit_value(MAX_LIMIT + 1_000), MAX_LIMIT);
        assert_eq!(clamp_limit_value(0), 1);
        assert_eq!(clamp_limit_value(50), 50);
    }
}
