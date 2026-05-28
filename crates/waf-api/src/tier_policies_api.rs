//! Tier policies API — GET/PUT /api/tier-policies, POST /api/tier-policies/dry-run.
//!
//! Config source: `configs/tier-policies.yaml`. The FE `TierConfig` maps
//! directly to the YAML structure (no wrapper key).

use std::sync::Arc;

use axum::{Json, extract::State};
use serde_json::{Value, json};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

fn resolve_path(state: &AppState, relative: &str) -> std::path::PathBuf {
    state.main_config_file.as_ref().map_or_else(
        || std::path::PathBuf::from(relative),
        |main| {
            let p = std::path::Path::new(main.as_str());
            let root = p.parent().and_then(|c| c.parent()).unwrap_or_else(|| std::path::Path::new("."));
            root.join(relative)
        },
    )
}

async fn read_yaml_opt(path: &std::path::Path) -> Option<Value> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    serde_yaml::from_str::<Value>(&raw).ok()
}

async fn write_yaml(path: &std::path::Path, value: &Value) -> Result<(), ApiError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| ApiError::Internal(anyhow::anyhow!("mkdir: {e}")))?;
    }
    let s = serde_yaml::to_string(value).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    let tmp = path.with_extension("yaml.tmp");
    tokio::fs::write(&tmp, s.as_bytes())
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("write: {e}")))?;
    tokio::fs::rename(&tmp, path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("rename: {e}")))?;
    Ok(())
}

fn default_tier_config() -> Value {
    fn policy(fail: &str, rps: i64, cache: &str, allow: i64, challenge: i64, block: i64) -> Value {
        json!({
            "fail_mode": fail,
            "ddos_threshold_rps": rps,
            "cache_policy": cache,
            "risk_thresholds": { "allow": allow, "challenge": challenge, "block": block }
        })
    }
    json!({
        "policies": {
            "critical":  policy("close", 50,   "no_cache",   20, 60, 85),
            "high":      policy("close", 200,  "default",    20, 60, 85),
            "medium":    policy("open",  500,  "short_ttl",  20, 60, 85),
            "catch_all": policy("open",  1000, "aggressive", 20, 60, 85)
        },
        "classifier_rules": []
    })
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_tier_policies(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/tier-policies.yaml");
    let cfg = read_yaml_opt(&path).await.unwrap_or_else(default_tier_config);
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_tier_policies(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    // Basic validation: all four tiers must be present
    for tier in &["critical", "high", "medium", "catch_all"] {
        let policies = body.get("policies").and_then(|p| p.get(*tier));
        if policies.is_none_or(Value::is_null) {
            return Err(ApiError::BadRequest(format!("missing tier: {tier}")));
        }
        let thresh = policies.and_then(|p| p.get("risk_thresholds")).cloned().unwrap_or(Value::Null);
        let allow = thresh.get("allow").and_then(Value::as_i64).unwrap_or(0);
        let challenge = thresh.get("challenge").and_then(Value::as_i64).unwrap_or(0);
        let block = thresh.get("block").and_then(Value::as_i64).unwrap_or(0);
        if !(allow < challenge && challenge < block) {
            return Err(ApiError::BadRequest(format!(
                "tier {tier}: risk thresholds must satisfy allow < challenge < block"
            )));
        }
    }

    let path = resolve_path(&state, "configs/tier-policies.yaml");
    write_yaml(&path, &body).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn dry_run_tier(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/tier-policies.yaml");
    let cfg = read_yaml_opt(&path).await.unwrap_or_else(default_tier_config);

    let method = body.get("method").and_then(Value::as_str).unwrap_or("GET");
    let path_str = body.get("path").and_then(Value::as_str).unwrap_or("/");

    // Simple classification: match classifier_rules by priority, fall back to catch_all
    let rules = cfg.get("classifier_rules").and_then(Value::as_array);
    let mut matched_tier = String::from("catch_all");
    let mut matched_id: Option<i64> = None;

    if let Some(rules) = rules {
        let mut sorted = rules.clone();
        sorted.sort_by_key(|r| std::cmp::Reverse(r.get("priority").and_then(Value::as_i64).unwrap_or(0)));

        for rule in &sorted {
            let tier = rule.get("tier").and_then(Value::as_str).unwrap_or("catch_all");
            let method_match = rule
                .get("methods")
                .and_then(Value::as_array)
                .map_or(true, |ms| {
                    ms.iter()
                        .any(|m| m.as_str().is_some_and(|s| s.eq_ignore_ascii_case(method)))
                });
            let path_match = rule
                .get("path_match")
                .and_then(Value::as_str)
                .map_or(true, |p| path_str.starts_with(p));

            if method_match && path_match {
                tier.clone_into(&mut matched_tier);
                matched_id = rule.get("id").and_then(Value::as_i64);
                break;
            }
        }
    }

    let policy = cfg
        .get("policies")
        .and_then(|p| p.get(matched_tier.as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    Ok(Json(json!({
        "success": true,
        "data": {
            "matched_tier": matched_tier,
            "matched_rule_id": matched_id,
            "policy": policy
        }
    })))
}
