//! Tier policies API — GET/PUT `/api/tier-policies`, POST `/api/tier-policies/dry-run`.
//!
//! Config source: `configs/tier-policies.yaml`. PUT validates the body with
//! typed serde structs, requires the `admin` role, and writes atomically via
//! tmp-file + rename. Body size is capped at 256 KiB by the route layer.

use std::path::Path;
use std::sync::Arc;

use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Max body size for tier-policies PUT/dry-run requests (256 KiB).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

// ─── Typed request models ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskThresholds {
    pub allow: i64,
    pub challenge: i64,
    pub block: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierPolicy {
    pub fail_mode: String,
    pub ddos_threshold_rps: i64,
    pub cache_policy: String,
    pub risk_thresholds: RiskThresholds,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierPolicyMap {
    pub critical: TierPolicy,
    pub high: TierPolicy,
    pub medium: TierPolicy,
    pub catch_all: TierPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierRule {
    pub id: Option<i64>,
    pub priority: Option<i64>,
    pub tier: String,
    #[serde(default)]
    pub methods: Option<Vec<String>>,
    #[serde(default)]
    pub path_match: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierConfig {
    pub policies: TierPolicyMap,
    #[serde(default)]
    pub classifier_rules: Vec<ClassifierRule>,
}

#[derive(Debug, Deserialize)]
pub struct DryRunRequest {
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
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

async fn read_yaml_opt<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    match serde_yaml::from_str::<T>(&raw) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "tier-policies: YAML parse failed; falling back to defaults");
            None
        }
    }
}

async fn write_yaml<T: Serialize + Sync>(path: &Path, value: &T) -> Result<(), ApiError> {
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

fn default_tier_config() -> TierConfig {
    fn policy(fail: &str, rps: i64, cache: &str, allow: i64, challenge: i64, block: i64) -> TierPolicy {
        TierPolicy {
            fail_mode: fail.to_string(),
            ddos_threshold_rps: rps,
            cache_policy: cache.to_string(),
            risk_thresholds: RiskThresholds {
                allow,
                challenge,
                block,
            },
        }
    }
    TierConfig {
        policies: TierPolicyMap {
            critical: policy("close", 50, "no_cache", 20, 60, 85),
            high: policy("close", 200, "default", 20, 60, 85),
            medium: policy("open", 500, "short_ttl", 20, 60, 85),
            catch_all: policy("open", 1000, "aggressive", 20, 60, 85),
        },
        classifier_rules: Vec::new(),
    }
}

fn validate_thresholds(tier: &str, t: &RiskThresholds) -> Result<(), ApiError> {
    if !(t.allow < t.challenge && t.challenge < t.block) {
        return Err(ApiError::BadRequest(format!(
            "tier {tier}: risk thresholds must satisfy allow < challenge < block"
        )));
    }
    Ok(())
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn get_tier_policies(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/tier-policies.yaml");
    let cfg = read_yaml_opt::<TierConfig>(&path)
        .await
        .unwrap_or_else(default_tier_config);
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_tier_policies(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<TierConfig>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;

    validate_thresholds("critical", &body.policies.critical.risk_thresholds)?;
    validate_thresholds("high", &body.policies.high.risk_thresholds)?;
    validate_thresholds("medium", &body.policies.medium.risk_thresholds)?;
    validate_thresholds("catch_all", &body.policies.catch_all.risk_thresholds)?;

    let path = resolve_under_root(&state, "configs/tier-policies.yaml");
    write_yaml(&path, &body).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn dry_run_tier(
    State(state): State<Arc<AppState>>,
    Json(req): Json<DryRunRequest>,
) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/tier-policies.yaml");
    let cfg = read_yaml_opt::<TierConfig>(&path)
        .await
        .unwrap_or_else(default_tier_config);

    let method = req.method.as_deref().unwrap_or("GET");
    let path_str = req.path.as_deref().unwrap_or("/");

    let mut sorted = cfg.classifier_rules.clone();
    sorted.sort_by_key(|r| std::cmp::Reverse(r.priority.unwrap_or(0)));

    let mut matched_tier = String::from("catch_all");
    let mut matched_id: Option<i64> = None;
    for rule in &sorted {
        let method_match = rule
            .methods
            .as_ref()
            .is_none_or(|ms| ms.iter().any(|m| m.eq_ignore_ascii_case(method)));
        let path_match = rule
            .path_match
            .as_ref()
            .is_none_or(|p| path_str.starts_with(p.as_str()));
        if method_match && path_match {
            rule.tier.clone_into(&mut matched_tier);
            matched_id = rule.id;
            break;
        }
    }

    let policy = match matched_tier.as_str() {
        "critical" => &cfg.policies.critical,
        "high" => &cfg.policies.high,
        "medium" => &cfg.policies.medium,
        _ => &cfg.policies.catch_all,
    };

    Ok(Json(json!({
        "success": true,
        "data": {
            "matched_tier": matched_tier,
            "matched_rule_id": matched_id,
            "policy": policy
        }
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = default_tier_config();
        validate_thresholds("critical", &cfg.policies.critical.risk_thresholds).unwrap();
        validate_thresholds("high", &cfg.policies.high.risk_thresholds).unwrap();
        validate_thresholds("medium", &cfg.policies.medium.risk_thresholds).unwrap();
        validate_thresholds("catch_all", &cfg.policies.catch_all.risk_thresholds).unwrap();
    }

    #[test]
    fn threshold_ordering_rejects_equal_bounds() {
        let bad = RiskThresholds {
            allow: 20,
            challenge: 20,
            block: 85,
        };
        let err = validate_thresholds("critical", &bad).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)));
    }

    #[test]
    fn threshold_ordering_rejects_inverted_bounds() {
        let bad = RiskThresholds {
            allow: 80,
            challenge: 60,
            block: 85,
        };
        assert!(validate_thresholds("high", &bad).is_err());
    }

    #[test]
    fn threshold_ordering_accepts_strict_increasing() {
        let ok = RiskThresholds {
            allow: 10,
            challenge: 50,
            block: 90,
        };
        assert!(validate_thresholds("medium", &ok).is_ok());
    }
}
