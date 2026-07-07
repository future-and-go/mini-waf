//! Tier policies API — GET/PUT /api/tier-policies, POST /api/tier-policies/dry-run.
//!
//! Config source: the tiered-protection TOML the engine watcher loads
//! (`[tiered_protection] config_path`, e.g. `configs/tier-protection.toml`).
//! Every payload round-trips through `waf_common::tier::TierConfig` and the
//! same snapshot build the gateway watcher runs, so a config this API accepts
//! is a config enforcement can load — and a save hot-reloads into the live
//! classifier via the watcher's rename event.
//!
//! The target file is panel-owned: PUT rewrites it in full as a bare
//! `[tiered_protection]` table, so `config_path` must point at a dedicated
//! file (co-located tables and comments do not survive a save).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::http::{HeaderMap, Method};
use axum::{Json, extract::State};
use gateway::tiered::{RequestParts, TierClassifier, TierSnapshot};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use waf_common::tier::{Tier, TierConfig, TierPolicy};

use crate::config_files::{resolve_path, write_toml_str};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// On-disk envelope: the watcher requires the `[tiered_protection]` table.
/// (`gateway::tiered`'s own envelope struct is private, so mirror it here;
/// the PUT test proves both sides stay in sync via `try_reload`.)
#[derive(Debug, Serialize, Deserialize)]
struct TierProtectionFile {
    tiered_protection: TierConfig,
}

/// Path to the tier TOML: the exact path the engine watcher was spawned with,
/// falling back to the conventional location when the profile leaves
/// `[tiered_protection]` unset (edits then take effect once a profile wires
/// `config_path`).
fn tier_toml_path(state: &AppState) -> PathBuf {
    state
        .tier_config_path
        .clone()
        .unwrap_or_else(|| resolve_path(state, "configs/tier-protection.toml"))
}

/// Config served when no file exists yet — the engine's boot-time fallback
/// (everything defaults to `TierPolicy::default()`, no classifier rules).
fn default_tier_config() -> TierConfig {
    TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: Vec::new(),
        policies: Tier::ALL.iter().map(|t| (*t, TierPolicy::default())).collect(),
    }
}

/// Parse a request body as an engine `TierConfig` and run the same snapshot
/// build the gateway watcher runs (all-tiers-present, threshold ordering,
/// regex compilation). Rejecting here is exactly what the watcher would do.
fn parse_and_validate(body: Value) -> Result<TierConfig, ApiError> {
    let cfg: TierConfig =
        serde_json::from_value(body).map_err(|e| ApiError::BadRequest(format!("invalid tier config: {e}")))?;
    TierSnapshot::try_from_config(cfg.clone())
        .map_err(|e| ApiError::BadRequest(format!("invalid tier config: {e}")))?;
    Ok(cfg)
}

/// Load the current config from disk. Missing file → engine boot defaults;
/// a file that exists but fails to parse is an operator problem and surfaces
/// as a 500 rather than being masked with defaults.
async fn load_tier_config(path: &Path) -> Result<TierConfig, ApiError> {
    match tokio::fs::read_to_string(path).await {
        Ok(raw) => {
            let file: TierProtectionFile = toml::from_str(&raw).map_err(|e| {
                ApiError::Internal(anyhow::anyhow!("tier config {} failed to parse: {e}", path.display()))
            })?;
            Ok(file.tiered_protection)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(default_tier_config()),
        Err(e) => Err(ApiError::Internal(anyhow::anyhow!("read {}: {e}", path.display()))),
    }
}

fn serialize_toml(cfg: TierConfig) -> Result<(String, TierConfig), ApiError> {
    let file = TierProtectionFile { tiered_protection: cfg };
    let toml_str =
        toml::to_string_pretty(&file).map_err(|e| ApiError::Internal(anyhow::anyhow!("serialize tier config: {e}")))?;
    Ok((toml_str, file.tiered_protection))
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_tier_policies(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let cfg = load_tier_config(&tier_toml_path(&state)).await?;
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_tier_policies(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let cfg = parse_and_validate(body)?;
    let (toml_str, cfg) = serialize_toml(cfg)?;
    write_toml_str(&tier_toml_path(&state), &toml_str).await?;
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn dry_run_tier(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let method_str = body.get("method").and_then(Value::as_str).unwrap_or("GET");
    let path_str = body.get("path").and_then(Value::as_str).unwrap_or("/");
    let host = body
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase();
    let method: Method = method_str
        .to_ascii_uppercase()
        .parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid method: {method_str}")))?;

    let cfg = load_tier_config(&tier_toml_path(&state)).await?;
    // Production matcher, not a reimplementation: compile the same classifier
    // the gateway serves so dry-run answers match live classification.
    let classifier = TierClassifier::new(&cfg.classifier_rules, cfg.default_tier)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("compile classifier: {e}")))?;
    let headers = HeaderMap::new();
    let tier = classifier.classify(&RequestParts {
        host: &host,
        path: path_str,
        method: &method,
        headers: &headers,
    });
    let policy = cfg.policies.get(&tier).cloned();
    Ok(Json(
        json!({ "success": true, "data": { "matched_tier": tier, "policy": policy } }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use waf_common::tier::{CachePolicy, FailMode, HttpMethod, RiskThresholds, TierClassifierRule};
    use waf_common::tier_match::PathMatch;

    fn valid_config() -> TierConfig {
        let mut cfg = default_tier_config();
        cfg.classifier_rules = vec![
            TierClassifierRule {
                priority: 100,
                tier: Tier::Critical,
                host: None,
                path: Some(PathMatch::Regex {
                    value: r"^/api/v\d+/pay".into(),
                }),
                method: Some(vec![HttpMethod::Post]),
                headers: None,
            },
            TierClassifierRule {
                priority: 50,
                tier: Tier::High,
                host: None,
                path: Some(PathMatch::Prefix {
                    value: "/account".into(),
                }),
                method: None,
                headers: None,
            },
        ];
        cfg.policies.insert(
            Tier::Critical,
            TierPolicy {
                fail_mode: FailMode::Close,
                ddos_threshold_rps: 50,
                cache_policy: CachePolicy::ShortTtl { ttl_seconds: 5 },
                risk_thresholds: RiskThresholds {
                    allow: 20,
                    challenge: 50,
                    block: 70,
                },
            },
        );
        cfg
    }

    /// The shipped file must parse through this module's envelope and build a
    /// snapshot — guards against the panel writing a file enforcement rejects.
    #[test]
    fn shipped_tier_protection_toml_round_trips() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../configs/tier-protection.toml"
        ))
        .expect("shipped config readable");
        let file: TierProtectionFile = toml::from_str(&raw).expect("shipped config parses");
        TierSnapshot::try_from_config(file.tiered_protection).expect("shipped config builds snapshot");
    }

    /// What PUT writes is byte-for-byte loadable by the gateway watcher's own
    /// entry point (`try_reload`) — the watcher-equivalence proof for saves,
    /// including rules whose `Option` fields are `None` (the `toml` crate must
    /// omit them, not error).
    #[test]
    fn put_serialization_loads_through_watcher_reload() {
        let (toml_str, _) = serialize_toml(valid_config()).expect("serializes");
        let dir = std::env::temp_dir().join(format!("tier-put-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join("tier-protection.toml");
        std::fs::write(&path, &toml_str).expect("write");
        let snap = gateway::tiered::try_reload(&path).expect("watcher loads what PUT writes");
        assert_eq!(snap.classifier.rule_count(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// JSON round-trip: what GET serves, PUT accepts unchanged.
    #[test]
    fn get_json_shape_is_put_compatible() {
        let json = serde_json::to_value(valid_config()).expect("to json");
        parse_and_validate(json).expect("round-trips");
    }

    #[test]
    fn put_rejects_bad_thresholds_missing_tier_and_bad_regex() {
        let mut bad = valid_config();
        bad.policies.get_mut(&Tier::Critical).unwrap().risk_thresholds = RiskThresholds {
            allow: 50,
            challenge: 50,
            block: 70,
        };
        let err = parse_and_validate(serde_json::to_value(bad).unwrap()).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "thresholds: {err}");

        let mut missing = valid_config();
        missing.policies.remove(&Tier::Medium);
        let err = parse_and_validate(serde_json::to_value(missing).unwrap()).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "missing tier: {err}");

        let mut bad_regex = valid_config();
        bad_regex.classifier_rules.get_mut(0).expect("rule").path = Some(PathMatch::Regex { value: "(".into() });
        let err = parse_and_validate(serde_json::to_value(bad_regex).unwrap()).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(_)), "bad regex: {err}");
    }

    /// Unknown-shape payloads (the old YAML flat `cache_policy` string) are
    /// rejected instead of being written to the enforcement file.
    #[test]
    fn put_rejects_legacy_flat_cache_policy_shape() {
        let legacy = json!({
            "default_tier": "catch_all",
            "classifier_rules": [],
            "policies": {
                "critical":  { "fail_mode": "close", "ddos_threshold_rps": 50, "cache_policy": "no_cache",
                               "risk_thresholds": { "allow": 20, "challenge": 60, "block": 85 } },
                "high":      { "fail_mode": "close", "ddos_threshold_rps": 200, "cache_policy": "default",
                               "risk_thresholds": { "allow": 20, "challenge": 60, "block": 85 } },
                "medium":    { "fail_mode": "open", "ddos_threshold_rps": 500, "cache_policy": "short_ttl",
                               "risk_thresholds": { "allow": 20, "challenge": 60, "block": 85 } },
                "catch_all": { "fail_mode": "open", "ddos_threshold_rps": 1000, "cache_policy": "aggressive",
                               "risk_thresholds": { "allow": 20, "challenge": 60, "block": 85 } }
            }
        });
        assert!(matches!(parse_and_validate(legacy), Err(ApiError::BadRequest(_))));
    }

    /// Dry-run uses the production classifier: regex + method AND-matching and
    /// priority ordering behave exactly as enforcement.
    #[test]
    fn dry_run_classifier_matches_engine_semantics() {
        let cfg = valid_config();
        let classifier = TierClassifier::new(&cfg.classifier_rules, cfg.default_tier).expect("compiles");
        let headers = HeaderMap::new();
        let classify = |method: Method, path: &str| {
            classifier.classify(&RequestParts {
                host: "",
                path,
                method: &method,
                headers: &headers,
            })
        };
        assert_eq!(classify(Method::POST, "/api/v2/pay"), Tier::Critical);
        assert_eq!(
            classify(Method::GET, "/api/v2/pay"),
            Tier::CatchAll,
            "method must AND with path"
        );
        assert_eq!(classify(Method::GET, "/account/settings"), Tier::High);
        assert_eq!(classify(Method::GET, "/anything"), Tier::CatchAll);
    }

    /// Missing file serves the engine's boot-time fallback shape.
    #[tokio::test]
    async fn load_missing_file_yields_engine_defaults() {
        let cfg = load_tier_config(Path::new("/nonexistent/tier-protection.toml"))
            .await
            .expect("defaults");
        assert_eq!(cfg.default_tier, Tier::CatchAll);
        assert!(cfg.classifier_rules.is_empty());
        assert_eq!(cfg.policies.len(), 4);
    }
}
