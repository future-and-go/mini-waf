//! Rule sources management API — DB-backed CRUD over the `rule_sources` table.
//!
//! Endpoints:
//!   GET    `/api/rule-sources`              — list configured external sources
//!   POST   `/api/rule-sources`              — add a new source
//!   DELETE `/api/rule-sources/{name}`       — remove a source by name
//!   POST   `/api/rule-sources/sync`         — bump `last_updated` for every
//!                                             source + trigger engine reload
//!   POST   `/api/rule-sources/{name}/sync`  — same, single source
//!
//! ## Scope
//!
//! Wires the admin UI page at `/ui/#/rule-sources` to the existing
//! `rule_sources` `PostgreSQL` table (`migrations/0007_rule_management.sql`).
//! The page previously emitted `Network Error` because no backend handler
//! existed for `/api/rule-sources`.
//!
//! Built-in sources (OWASP/bot/scanner) are NOT stored in the table — they
//! are hardcoded in the frontend's "Built-in Sources" panel and managed via
//! `[rules].enable_builtin_*` flags in the TOML config.
//!
//! Engine integration (actually loading rules from the DB-backed sources at
//! request time) is intentionally out of scope; the runtime engine still
//! reads from `[rules.sources]` in the TOML config + filesystem rules dir.
//! Sources added through this API are persisted in the DB and surfaced in
//! the admin UI but are NOT activated until that hook is added in a follow-up.

use std::sync::Arc;

use anyhow::anyhow;
use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct RuleSourceRow {
    name: String,
    source_type: String,
    url: Option<String>,
    path: Option<String>,
    format: String,
    enabled: bool,
    last_updated: Option<DateTime<Utc>>,
}

// ── Output type ───────────────────────────────────────────────────────────────

/// Wire shape consumed by the React admin panel
/// (`web/admin-panel/src/types/api.ts::RuleSource`) and the legacy Vue
/// admin-ui (`web/admin-ui/src/views/RuleSources.vue`).
///
/// Field naming intentionally uses `camelCase` for the date — both frontends
/// already key on `lastUpdated`.
#[derive(Debug, Serialize)]
struct RuleSourceDto {
    name: String,
    #[serde(rename = "type")]
    source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
    format: String,
    enabled: bool,
    #[serde(rename = "lastUpdated", skip_serializing_if = "Option::is_none")]
    last_updated: Option<DateTime<Utc>>,
}

impl From<RuleSourceRow> for RuleSourceDto {
    fn from(r: RuleSourceRow) -> Self {
        Self {
            name: r.name,
            source_type: r.source_type,
            url: r.url,
            path: r.path,
            format: r.format,
            enabled: r.enabled,
            last_updated: r.last_updated,
        }
    }
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct CreateRuleSourceRequest {
    pub name: String,
    pub source_type: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default = "default_format")]
    pub format: String,
    /// Accepted from the frontend form but currently not persisted — there is
    /// no `update_interval` column on `rule_sources` and the engine doesn't
    /// consume it yet. Field kept on the request type so the existing FE
    /// payload deserialises cleanly without a `400 Bad Request`.
    #[serde(default)]
    pub update_interval: Option<u64>,
}

fn default_format() -> String {
    "yaml".to_string()
}

// ── Validation ────────────────────────────────────────────────────────────────

/// Mirrors the column widths in `migrations/0007_rule_management.sql`.
const MAX_NAME_LEN: usize = 100;
const MAX_URL_LEN: usize = 1000;
const MAX_PATH_LEN: usize = 500;
const MAX_FORMAT_LEN: usize = 20;

const ALLOWED_SOURCE_TYPES: &[&str] = &["local_file", "local_dir", "remote_url"];
const ALLOWED_FORMATS: &[&str] = &["yaml", "json", "modsec"];

fn validate_request(req: &CreateRuleSourceRequest) -> Result<(), &'static str> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err("name must not be empty");
    }
    if name.len() > MAX_NAME_LEN {
        return Err("name too long (max 100 chars)");
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':' | b'.'))
    {
        return Err("name only allows ASCII alnum and `_`, `-`, `:`, `.`");
    }
    if !ALLOWED_SOURCE_TYPES.contains(&req.source_type.as_str()) {
        return Err("source_type must be one of: local_file, local_dir, remote_url");
    }
    if !ALLOWED_FORMATS.contains(&req.format.as_str()) {
        return Err("format must be one of: yaml, json, modsec");
    }
    if req.format.len() > MAX_FORMAT_LEN {
        return Err("format too long");
    }
    if let Some(u) = &req.url
        && u.len() > MAX_URL_LEN
    {
        return Err("url too long (max 1000 chars)");
    }
    if let Some(p) = &req.path
        && p.len() > MAX_PATH_LEN
    {
        return Err("path too long (max 500 chars)");
    }
    // remote_url MUST have url; local_* MUST have path. We don't validate the
    // URL scheme here — a separate FR-002b SSRF guard owns that surface.
    match req.source_type.as_str() {
        "remote_url" => {
            if req.url.as_deref().is_none_or(str::is_empty) {
                return Err("remote_url source requires a non-empty url");
            }
        }
        "local_file" | "local_dir" => {
            if req.path.as_deref().is_none_or(str::is_empty) {
                return Err("local_file/local_dir source requires a non-empty path");
            }
        }
        _ => {}
    }
    Ok(())
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// `GET /api/rule-sources` — list all DB-backed external sources.
pub async fn list_rule_sources(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let rows: Vec<RuleSourceRow> = sqlx::query_as(
        "SELECT name, source_type, url, path, format, enabled, last_updated \
         FROM rule_sources ORDER BY name ASC",
    )
    .fetch_all(state.db.pool())
    .await
    .map_err(|e| ApiError::Internal(anyhow!(e)))?;

    let sources: Vec<RuleSourceDto> = rows.into_iter().map(RuleSourceDto::from).collect();
    Ok(Json(json!({ "sources": sources })))
}

/// `POST /api/rule-sources` — insert a new external rule source.
///
/// Returns `409 Conflict` when `name` already exists (UNIQUE constraint).
pub async fn create_rule_source(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateRuleSourceRequest>,
) -> impl IntoResponse {
    if let Err(reason) = validate_request(&req) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "ok": false, "error": format!("invalid request: {reason}") })),
        )
            .into_response();
    }

    let result = sqlx::query(
        r"INSERT INTO rule_sources (name, source_type, url, path, format, enabled)
          VALUES ($1, $2, $3, $4, $5, true)",
    )
    .bind(req.name.trim())
    .bind(&req.source_type)
    .bind(req.url.as_deref())
    .bind(req.path.as_deref())
    .bind(&req.format)
    .execute(state.db.pool())
    .await;

    match result {
        Ok(_) => (StatusCode::CREATED, Json(json!({ "ok": true, "name": req.name }))).into_response(),
        Err(e) => {
            if let Some(db_err) = e.as_database_error()
                && db_err.is_unique_violation()
            {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({ "ok": false, "error": format!("rule source '{}' already exists", req.name) })),
                )
                    .into_response();
            }
            warn!(error = %e, "failed to insert rule source");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": e.to_string() })),
            )
                .into_response()
        }
    }
}

/// `DELETE /api/rule-sources/{name}` — remove a source by name.
pub async fn delete_rule_source(
    State(state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    let affected = sqlx::query("DELETE FROM rule_sources WHERE name = $1")
        .bind(&name)
        .execute(state.db.pool())
        .await
        .map_or(0, |r| r.rows_affected());

    if affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": format!("rule source '{name}' not found") })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({ "ok": true, "name": name }))).into_response()
}

/// `POST /api/rule-sources/sync` — bump `last_updated = NOW()` for every row
/// and trigger a full engine reload.
pub async fn sync_all_rule_sources(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let touched = sqlx::query("UPDATE rule_sources SET last_updated = NOW(), updated_at = NOW()")
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::Internal(anyhow!(e)))?
        .rows_affected();

    state.engine.reload_rules().await.map_err(ApiError::Internal)?;

    Ok(Json(json!({ "ok": true, "touched": touched })))
}

/// `POST /api/rule-sources/{name}/sync` — bump `last_updated` for one row +
/// trigger reload. Returns 404 if the row is missing.
pub async fn sync_rule_source(
    State(state): State<Arc<AppState>>,
    AxumPath(name): AxumPath<String>,
) -> impl IntoResponse {
    let result = sqlx::query("UPDATE rule_sources SET last_updated = NOW(), updated_at = NOW() WHERE name = $1")
        .bind(&name)
        .execute(state.db.pool())
        .await;
    let affected = match result {
        Ok(r) => r.rows_affected(),
        Err(e) => {
            warn!(error = %e, name = %name, "failed to update rule source last_updated");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "ok": false, "error": e.to_string() })),
            )
                .into_response();
        }
    };
    if affected == 0 {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "ok": false, "error": format!("rule source '{name}' not found") })),
        )
            .into_response();
    }
    if let Err(e) = state.engine.reload_rules().await {
        warn!(error = %e, "engine reload failed during single-source sync");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "ok": false, "error": e.to_string() })),
        )
            .into_response();
    }
    (StatusCode::OK, Json(json!({ "ok": true, "name": name }))).into_response()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use .expect() for controlled panics
mod tests {
    use super::*;

    fn req(name: &str, source_type: &str, url: Option<&str>, path: Option<&str>) -> CreateRuleSourceRequest {
        CreateRuleSourceRequest {
            name: name.to_string(),
            source_type: source_type.to_string(),
            url: url.map(str::to_string),
            path: path.map(str::to_string),
            format: "yaml".to_string(),
            _update_interval: None,
        }
    }

    #[test]
    fn validate_accepts_well_formed_remote_url() {
        let r = req("crs-extras", "remote_url", Some("https://example.com/rules.yaml"), None);
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_accepts_well_formed_local_dir() {
        let r = req("ops-rules", "local_dir", None, Some("/etc/prx-waf/rules"));
        assert!(validate_request(&r).is_ok());
    }

    #[test]
    fn validate_rejects_remote_url_without_url() {
        let r = req("missing", "remote_url", None, None);
        assert_eq!(validate_request(&r), Err("remote_url source requires a non-empty url"));
    }

    #[test]
    fn validate_rejects_local_file_without_path() {
        let r = req("missing", "local_file", None, None);
        assert_eq!(
            validate_request(&r),
            Err("local_file/local_dir source requires a non-empty path")
        );
    }

    #[test]
    fn validate_rejects_unknown_source_type() {
        let r = req("x", "ftp_pull", Some("ftp://x"), None);
        assert!(validate_request(&r).is_err());
    }

    #[test]
    fn validate_rejects_unknown_format() {
        let mut r = req("x", "remote_url", Some("https://e/r.yaml"), None);
        r.format = "xml".to_string();
        assert_eq!(validate_request(&r), Err("format must be one of: yaml, json, modsec"));
    }

    #[test]
    fn validate_rejects_name_with_disallowed_chars() {
        let r = req("bad name!", "remote_url", Some("https://e/r.yaml"), None);
        assert_eq!(
            validate_request(&r),
            Err("name only allows ASCII alnum and `_`, `-`, `:`, `.`")
        );
    }

    #[test]
    fn validate_rejects_blank_name() {
        let r = req("   ", "remote_url", Some("https://e/r.yaml"), None);
        assert_eq!(validate_request(&r), Err("name must not be empty"));
    }

    /// Frontend sends `update_interval` in the payload. Confirm it
    /// deserialises into the request type even though it is not persisted.
    /// Without `#[serde(rename = "update_interval")]` the field would be a
    /// non-snake JSON key mismatch and refine would surface an error toast.
    #[test]
    fn create_request_accepts_update_interval_field() {
        let body = r#"{"name":"x","source_type":"remote_url","url":"https://e/r.yaml","format":"yaml","update_interval":86400}"#;
        let parsed: CreateRuleSourceRequest = serde_json::from_str(body).expect("parse body");
        assert_eq!(parsed.name, "x");
        assert_eq!(parsed.update_interval, Some(86400));
    }
}
