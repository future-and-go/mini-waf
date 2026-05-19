//! Bot pattern management API.
//!
//! Endpoints:
//!   GET   /api/bot-patterns        — list all patterns (builtin + custom DB rows)
//!   POST  /api/bot-patterns        — create a custom pattern (stored in DB)
//!   PATCH /api/bot-patterns/:id    — toggle enabled state
//!
//! Built-in patterns come from `waf_engine::rules::builtin::bot::rules()` and
//! are prefixed with their rule id (e.g. "BOT-GOOD-001"). Their enabled state
//! is stored in the shared `rule_overrides` table (host_id IS NULL).
//!
//! Custom patterns stored in the `bot_patterns` DB table are exposed with an
//! id of "custom-{db_id}" and source="custom".

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use waf_engine::rules::builtin::bot;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct BotPatternRow {
    id: i32,
    name: String,
    pattern: String,
    action: String,
    #[allow(dead_code)]
    description: Option<String>,
    enabled: bool,
    tags: Vec<String>,
}

// ── Wire override row ─────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct OverrideRow {
    rule_id: String,
    enabled: Option<bool>,
}

// ── API types ─────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct BotPatternOut {
    pub id: String,
    pub name: String,
    pub pattern: String,
    pub action: String,
    pub tags: Vec<String>,
    pub enabled: bool,
    pub source: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateBotPatternReq {
    pub pattern: String,
    pub name: String,
    #[serde(default = "default_action")]
    pub action: String,
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_action() -> String {
    "block".to_string()
}

#[derive(Debug, Deserialize)]
pub struct ToggleBotPatternReq {
    pub enabled: bool,
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /api/bot-patterns
pub async fn list_bot_patterns(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // ── Builtin rules ─────────────────────────────────────────────────────────
    let builtin = bot::rules();

    // Fetch overrides for builtin rule ids
    let ids: Vec<String> = builtin.iter().map(|r| r.id.clone()).collect();
    let overrides: Vec<OverrideRow> = if ids.is_empty() {
        vec![]
    } else {
        sqlx::query_as::<_, OverrideRow>(
            "SELECT rule_id, enabled FROM rule_overrides WHERE host_id IS NULL AND rule_id = ANY($1)",
        )
        .bind(&ids)
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default()
    };

    let override_map: std::collections::HashMap<String, bool> = overrides
        .into_iter()
        .filter_map(|r| r.enabled.map(|e| (r.rule_id, e)))
        .collect();

    let builtin_out: Vec<BotPatternOut> = builtin
        .into_iter()
        .map(|r| {
            let enabled = override_map.get(&r.id).copied().unwrap_or(r.enabled);
            BotPatternOut {
                id: r.id.clone(),
                name: r.name,
                pattern: r.pattern.unwrap_or_default(),
                action: r.action,
                tags: r.tags,
                enabled,
                source: r.source,
            }
        })
        .collect();

    // ── Custom DB patterns ────────────────────────────────────────────────────
    let custom_rows: Vec<BotPatternRow> =
        sqlx::query_as::<_, BotPatternRow>(
            "SELECT id, name, pattern, action, description, enabled, tags FROM bot_patterns ORDER BY id",
        )
        .fetch_all(state.db.pool())
        .await
        .unwrap_or_default();

    let custom_out: Vec<BotPatternOut> = custom_rows
        .into_iter()
        .map(|r| BotPatternOut {
            id: format!("custom-{}", r.id),
            name: r.name,
            pattern: r.pattern,
            action: r.action,
            tags: r.tags,
            enabled: r.enabled,
            source: "custom".to_string(),
        })
        .collect();

    let mut patterns: Vec<BotPatternOut> = builtin_out;
    patterns.extend(custom_out);

    (
        StatusCode::OK,
        Json(json!({ "patterns": patterns })),
    )
}

/// POST /api/bot-patterns — create a custom pattern in DB
pub async fn create_bot_pattern(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateBotPatternReq>,
) -> ApiResult<Json<Value>> {
    if req.pattern.trim().is_empty() {
        return Err(ApiError::BadRequest("pattern must not be empty".into()));
    }
    if req.name.trim().is_empty() {
        return Err(ApiError::BadRequest("name must not be empty".into()));
    }

    let row: (i32,) = sqlx::query_as(
        r"INSERT INTO bot_patterns (name, pattern, action, description, tags)
          VALUES ($1, $2, $3, $4, $5)
          RETURNING id",
    )
    .bind(&req.name)
    .bind(&req.pattern)
    .bind(&req.action)
    .bind(&req.description)
    .bind(&req.tags)
    .fetch_one(state.db.pool())
    .await
    .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

    Ok(Json(json!({
        "success": true,
        "data": {
            "id": format!("custom-{}", row.0),
            "name": req.name,
            "pattern": req.pattern,
            "action": req.action,
            "tags": req.tags,
            "enabled": true,
            "source": "custom",
        }
    })))
}

/// PATCH /api/bot-patterns/:id — toggle enabled state
///
/// For builtin rules (id = "BOT-…") uses the shared `rule_overrides` table.
/// For custom patterns (id = "custom-{n}") updates the `bot_patterns` table.
pub async fn toggle_bot_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(req): Json<ToggleBotPatternReq>,
) -> ApiResult<Json<Value>> {
    if let Some(db_id_str) = id.strip_prefix("custom-") {
        let db_id: i32 = db_id_str
            .parse()
            .map_err(|_| ApiError::NotFound(format!("Invalid custom bot pattern id: {id}")))?;

        let updated = sqlx::query_scalar::<_, bool>(
            "UPDATE bot_patterns SET enabled = $1, updated_at = now() WHERE id = $2 RETURNING enabled",
        )
        .bind(req.enabled)
        .bind(db_id)
        .fetch_optional(state.db.pool())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;

        if updated.is_none() {
            return Err(ApiError::NotFound(format!("Custom bot pattern {id} not found")));
        }
    } else {
        // Builtin rule: upsert into rule_overrides (same table as registry toggle)
        sqlx::query(
            r"INSERT INTO rule_overrides (rule_id, host_id, enabled, updated_at)
              VALUES ($1, NULL, $2, now())
              ON CONFLICT (rule_id, host_id)
              DO UPDATE SET enabled = $2, updated_at = now()",
        )
        .bind(&id)
        .bind(req.enabled)
        .execute(state.db.pool())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    }

    Ok(Json(json!({
        "success": true,
        "data": { "id": id, "enabled": req.enabled }
    })))
}
