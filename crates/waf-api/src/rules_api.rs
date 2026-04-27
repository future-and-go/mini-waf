//! Rule registry API — exposes all YAML rule files from the filesystem.
//!
//! Endpoints:
//!   GET  /api/rules/registry           — list all rules from YAML files
//!   POST /api/rules/reload             — reload engine rules
//!   POST /api/rules/import             — import rules from a YAML file path
//!   PATCH /api/rules/registry/{id}     — enable / disable a rule (stored in `rule_overrides`)

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::anyhow;
use axum::{
    Json,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tracing::warn;

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ── YAML schema (minimal — only fields needed for the registry) ───────────────

#[derive(Debug, Deserialize)]
struct YamlRuleFile {
    #[serde(default)]
    source: String,
    #[serde(default)]
    rules: Vec<YamlRuleEntry>,
}

#[derive(Debug, Deserialize)]
struct YamlRuleEntry {
    id: String,
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: String,
    #[serde(default = "default_action")]
    action: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    pattern: Option<String>,
}

fn default_action() -> String {
    "block".to_string()
}

// ── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct RuleEntry {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
    pub source: String,
    pub enabled: bool,
    pub action: String,
    pub severity: Option<String>,
    pub pattern: Option<String>,
    pub tags: Vec<String>,
    pub file: String,
}

// ── DB row ────────────────────────────────────────────────────────────────────

#[derive(Debug, sqlx::FromRow)]
struct RuleOverrideRow {
    rule_id: String,
    enabled: Option<bool>,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ToggleRuleRequest {
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportRulesRequest {
    pub source: String,
    #[serde(default = "default_format")]
    pub format: String,
}

fn default_format() -> String {
    "yaml".to_string()
}

// ── Filesystem scanner ────────────────────────────────────────────────────────

/// Scan all `.yaml` files under `rules_dir` recursively and return rule entries.
fn scan_yaml_rules(rules_dir: &Path) -> Vec<(String, String, Vec<YamlRuleEntry>)> {
    let mut results: Vec<(String, String, Vec<YamlRuleEntry>)> = Vec::new();
    collect_yaml_files(rules_dir, rules_dir, &mut results);
    results
}

fn collect_yaml_files(base: &Path, dir: &Path, out: &mut Vec<(String, String, Vec<YamlRuleEntry>)>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!("Cannot read rules dir {}: {e}", dir.display());
            return;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_yaml_files(base, &path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        // Skip the sync-config.yaml meta file
        if path.file_name().and_then(|n| n.to_str()) == Some("sync-config.yaml") {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot read {}: {e}", path.display());
                continue;
            }
        };

        let rulefile: YamlRuleFile = match serde_yaml::from_str(&content) {
            Ok(r) => r,
            Err(e) => {
                warn!("Cannot parse {}: {e}", path.display());
                continue;
            }
        };

        // Derive a relative path label like "owasp-crs/sqli.yaml"
        let rel = path
            .strip_prefix(base)
            .map_or_else(|_| path.display().to_string(), |p| p.display().to_string());

        let source = if rulefile.source.is_empty() {
            // Derive source from directory name
            path.parent()
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string()
        } else {
            rulefile.source
        };

        out.push((rel, source, rulefile.rules));
    }
}

// ── Handlers ──────────────────────────────────────────────────────────────────

/// GET /api/rules/registry — list all rules from YAML files
pub async fn get_rule_registry(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Fetch all rule overrides from DB (global — host_id IS NULL)
    let overrides: Vec<RuleOverrideRow> =
        sqlx::query_as("SELECT rule_id, enabled FROM rule_overrides WHERE host_id IS NULL")
            .fetch_all(state.db.pool())
            .await
            .unwrap_or_default();

    let override_map: HashMap<String, bool> = overrides
        .into_iter()
        .filter_map(|r| r.enabled.map(|e| (r.rule_id, e)))
        .collect();

    // Scan rules directory
    let rules_dir = std::env::current_dir()
        .ok()
        .map(|d| d.join("rules"))
        .filter(|p| p.is_dir())
        .unwrap_or_else(|| Path::new("/app/rules").to_path_buf());

    let file_groups = scan_yaml_rules(&rules_dir);

    let mut rules: Vec<RuleEntry> = Vec::new();
    for (file, source, entries) in file_groups {
        for entry in entries {
            let enabled = override_map.get(&entry.id).copied().unwrap_or(true);
            let severity = if entry.severity.is_empty() {
                None
            } else {
                Some(entry.severity)
            };
            rules.push(RuleEntry {
                id: entry.id,
                name: entry.name,
                description: entry.description,
                category: entry.category,
                source: source.clone(),
                enabled,
                action: entry.action,
                severity,
                pattern: entry.pattern,
                tags: entry.tags,
                file: file.clone(),
            });
        }
    }

    let total = rules.len();
    let enabled = rules.iter().filter(|r| r.enabled).count();

    (
        StatusCode::OK,
        Json(json!({
            "rules": rules,
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
        })),
    )
}

/// PATCH `/api/rules/registry/:rule_id` — enable / disable a rule globally
pub async fn toggle_rule(
    State(state): State<Arc<AppState>>,
    AxumPath(rule_id): AxumPath<String>,
    Json(req): Json<ToggleRuleRequest>,
) -> ApiResult<Json<Value>> {
    // Upsert into rule_overrides with host_id = NULL (global scope)
    sqlx::query(
        r"INSERT INTO rule_overrides (rule_id, host_id, enabled, updated_at)
          VALUES ($1, NULL, $2, now())
          ON CONFLICT (rule_id, host_id)
          DO UPDATE SET enabled = $2, updated_at = now()",
    )
    .bind(&rule_id)
    .bind(req.enabled)
    .execute(state.db.pool())
    .await
    .map_err(|e| ApiError::Internal(anyhow!(e)))?;

    Ok(Json(json!({
        "success": true,
        "data": { "rule_id": rule_id, "enabled": req.enabled }
    })))
}

/// POST /api/rules/reload — reload engine rules
pub async fn reload_rule_registry(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    state.engine.reload_rules().await.map_err(ApiError::Internal)?;
    Ok(Json(json!({ "success": true, "data": "Rules reloaded" })))
}

/// POST /api/rules/import — import rules from a local file path (YAML only for now)
pub async fn import_rules(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ImportRulesRequest>,
) -> ApiResult<Json<Value>> {
    if req.format != "yaml" {
        return Err(ApiError::BadRequest(
            "Only 'yaml' format is supported for file import".into(),
        ));
    }

    let path = Path::new(&req.source);
    if !path.exists() {
        return Err(ApiError::NotFound(format!("File not found: {}", req.source)));
    }

    let content = std::fs::read_to_string(path).map_err(|e| ApiError::Internal(anyhow!("Cannot read file: {e}")))?;

    let rulefile: YamlRuleFile =
        serde_yaml::from_str(&content).map_err(|e| ApiError::BadRequest(format!("Invalid YAML: {e}")))?;

    let count = rulefile.rules.len();

    // Trigger engine reload to pick up new files
    state.engine.reload_rules().await.map_err(ApiError::Internal)?;

    Ok(Json(json!({
        "success": true,
        "data": {
            "imported": count,
            "source": req.source,
        }
    })))
}
