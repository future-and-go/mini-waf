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

/// YAML files that live under `rules/` but are NOT WAF rule files. They use
/// their own schema and are loaded by other subsystems:
///
/// * `sync-config.yaml`   — cluster rule-sync metadata
/// * `cache.yaml`         — FR-009 per-route response cache rules
///   (loaded by `gateway::cache::CacheRuleWatcher`)
/// * `access-lists.yaml`  — FR-008 access-list config (`version`, `ip_whitelist`,
///   `host_whitelist`, …). The multi-doc fallback would otherwise deserialize
///   the single top-level document as `YamlRuleEntry` and warn on the missing
///   `id` field on every reload.
///
/// Without this list the registry warning floods boot logs with
/// `Cannot parse cache.yaml: rules[0]: missing field 'name'` etc.
const NON_RULE_META_FILES: &[&str] = &["sync-config.yaml", "cache.yaml", "access-lists.yaml"];

/// Subdirectories of `rules/` that hold non-WAF-rule data and must not be
/// recursed into by the scanner.
///
/// * `threat-intel` — operator allow/deny overrides and hyperscaler ASN/CIDR
///   seed data loaded by `DatacenterSet::merge_yaml`. Documents look like
///   `asns: [...]` / `cidrs: [...]` and would warn on missing `id` otherwise.
const NON_RULE_DIRS: &[&str] = &["threat-intel"];

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
            // Skip data-only subdirs (e.g. threat-intel/) before recursing.
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| NON_RULE_DIRS.contains(&name))
            {
                continue;
            }
            collect_yaml_files(base, &path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        // Skip non-rule meta files (cluster sync, FR-009 cache rules, etc.).
        if path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| NON_RULE_META_FILES.contains(&name))
        {
            continue;
        }

        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!("Cannot read {}: {e}", path.display());
                continue;
            }
        };

        // Derive a relative path label like "owasp-crs/sqli.yaml"
        let rel = path
            .strip_prefix(base)
            .map_or_else(|_| path.display().to_string(), |p| p.display().to_string());

        let source_from_dir = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        // ── Try wrapped format: { source: "...", rules: [...] } ─────────────
        // Used by test fixtures and any externally-imported rule bundles.
        // NOTE: serde_yaml::from_str may return Err for multi-document files
        // (files containing `---` document separators); do NOT `continue` on
        // error — fall through to the flat multi-doc parser below.
        let wrapped_ok = match serde_yaml::from_str::<YamlRuleFile>(&content) {
            Ok(rulefile) if !rulefile.rules.is_empty() => {
                let source = if rulefile.source.is_empty() {
                    source_from_dir.clone()
                } else {
                    rulefile.source
                };
                out.push((rel.clone(), source, rulefile.rules));
                true
            }
            _ => false,
        };

        if wrapped_ok {
            continue;
        }

        // ── Multi-document flat format ─────────────────────────────────────
        // The built-in rules/*.yaml files use YAML multi-document syntax:
        // each `---` delimited document is a single YamlRuleEntry.
        // Example: rules/owasp-crs/sqli.yaml, rules/advanced/ssti.yaml, etc.
        let mut flat_entries: Vec<YamlRuleEntry> = Vec::new();
        for doc in serde_yaml::Deserializer::from_str(&content) {
            match YamlRuleEntry::deserialize(doc) {
                Ok(e) => flat_entries.push(e),
                Err(e) => {
                    warn!("Skipping rule doc in {rel}: {e}");
                }
            }
        }

        if flat_entries.is_empty() {
            warn!("No rules parsed from {}: check YAML format", path.display());
        } else {
            out.push((rel, source_from_dir, flat_entries));
        }
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::expect_used)] // Tests use .expect() for controlled panics
mod registry_scan_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Mirror of the layout the warning was observed with: a real WAF rule
    /// file plus FR-009 `cache.yaml`. The cache rule entries lack the `name`
    /// field that `YamlRuleEntry` requires, so naïve iteration would log
    /// `Cannot parse cache.yaml: rules[0]: missing field 'name'`. The skip
    /// list must keep the scanner silent on that file while still picking
    /// up the real WAF rule.
    ///
    /// To prove it is the **filename skip** (not the parse-error path) that
    /// excludes `cache.yaml`, we deliberately give the cache file a body that
    /// WOULD parse as a `YamlRuleFile` if it were attempted — a rule entry
    /// with a `name`. The skip list must still drop it on the file-name
    /// check before parsing kicks in. Without the `cache.yaml` entry in
    /// `NON_RULE_META_FILES`, this rule would leak into the registry
    /// response and the assertion below would fail.
    #[test]
    fn cache_yaml_is_skipped_by_filename_not_by_parse_error() {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("real-rules.yaml"),
            "source: test\nrules:\n  - id: r1\n    name: Real WAF rule\n    category: sqli\n",
        )
        .expect("write real-rules");
        // Note: this synthetic cache.yaml has `name:` so it WOULD parse as a
        // WAF rule. The skip list must catch it by filename anyway.
        fs::write(
            root.join("cache.yaml"),
            "rules:\n  - id: cache-not-a-waf-rule\n    name: Should be skipped by filename\n    category: cache\n",
        )
        .expect("write cache.yaml");
        fs::write(root.join("sync-config.yaml"), "rules:\n  - id: x\n    name: y\n").expect("write sync-config");

        let groups = scan_yaml_rules(root);
        let files: Vec<&str> = groups.iter().map(|(f, _, _)| f.as_str()).collect();
        assert_eq!(files, vec!["real-rules.yaml"]);
        let entries = groups.first().expect("at least one group");
        assert_eq!(entries.2.len(), 1);
        assert_eq!(entries.2.first().expect("rule entry").id, "r1");
    }

    /// `access-lists.yaml` has a single top-level document with no `id` field.
    /// Without the filename skip, the multi-doc fallback parser warns on every
    /// reload (`Skipping rule doc in access-lists.yaml: missing field 'id'`).
    /// Anything in `threat-intel/` is operator/ASN data loaded elsewhere and
    /// must not be recursed into.
    #[test]
    fn access_lists_and_threat_intel_are_skipped() {
        let dir = TempDir::new().expect("tempdir");
        let root = dir.path();
        fs::write(
            root.join("real-rules.yaml"),
            "source: test\nrules:\n  - id: r1\n    name: Real WAF rule\n    category: sqli\n",
        )
        .expect("write real-rules");
        fs::write(
            root.join("access-lists.yaml"),
            "version: 1\ndry_run: false\nip_whitelist: []\nip_blacklist: []\n",
        )
        .expect("write access-lists");
        fs::create_dir(root.join("threat-intel")).expect("mkdir threat-intel");
        fs::write(
            root.join("threat-intel").join("hyperscaler-asn-seed.yaml"),
            "asns:\n  - 16509\ncidrs: []\n",
        )
        .expect("write asn seed");

        let groups = scan_yaml_rules(root);
        let files: Vec<&str> = groups.iter().map(|(f, _, _)| f.as_str()).collect();
        assert_eq!(files, vec!["real-rules.yaml"]);
    }
}
