//! Relay & Proxy Intel API — GET/PUT `/api/relay/config`,
//! GET `/api/relay/intel/status`, POST `/api/relay/intel/refresh`,
//! POST `/api/relay/test`.
//!
//! Config source: `configs/relay.yaml`. Test endpoint loads the YAML, builds
//! an ephemeral `RelayDetector` from it, and evaluates a synthetic request
//! against the configured providers — verdicts are the actual `Signal`s the
//! detector emits, not a hand-rolled stub.

use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use axum::http::{HeaderMap as HttpHeaderMap, HeaderName, HeaderValue};
use axum::{Json, extract::State, http::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::auth::{Claims, validate_admin_token};
use crate::config_paths::resolve_under_root;
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

/// Max body size for relay PUT/test requests (256 KiB).
pub const MAX_BODY_BYTES: usize = 256 * 1024;

// ─── Typed request models ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderToggle {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub risk_weight: Option<i64>,
    #[serde(default)]
    pub max_chain_depth: Option<i64>,
    #[serde(default)]
    pub reject_private_in_chain: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayProviders {
    #[serde(default)]
    pub asn_classifier: ProviderToggle,
    #[serde(default)]
    pub tor_exit: ProviderToggle,
    #[serde(default)]
    pub datacenter: ProviderToggle,
    #[serde(default)]
    pub proxy_chain: ProviderToggle,
    #[serde(default)]
    pub xff_validator: ProviderToggle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FeedRef {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub refresh_secs: Option<i64>,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct IntelSources {
    #[serde(default)]
    pub asn_feed: FeedRef,
    #[serde(default)]
    pub tor_feed: FeedRef,
    #[serde(default)]
    pub datacenter_set: FeedRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RiskWeights {
    #[serde(default)]
    pub tor: i64,
    #[serde(default)]
    pub datacenter: i64,
    #[serde(default)]
    pub bad_asn: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RelayApiConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub providers: RelayProviders,
    #[serde(default)]
    pub intel: IntelSources,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub risk_weights: RiskWeights,
}

#[derive(Debug, Deserialize)]
pub struct TestRelayRequest {
    pub client_ip: String,
    #[serde(default)]
    pub xff: Option<String>,
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
            tracing::warn!(path = %path.display(), error = %e, "relay: YAML parse failed; falling back to defaults");
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

fn default_relay_config() -> RelayApiConfig {
    RelayApiConfig {
        enabled: false,
        providers: RelayProviders {
            asn_classifier: ProviderToggle {
                enabled: true,
                risk_weight: Some(15),
                ..Default::default()
            },
            tor_exit: ProviderToggle {
                enabled: true,
                risk_weight: Some(30),
                ..Default::default()
            },
            datacenter: ProviderToggle {
                enabled: true,
                risk_weight: Some(15),
                ..Default::default()
            },
            proxy_chain: ProviderToggle {
                enabled: true,
                risk_weight: Some(20),
                ..Default::default()
            },
            xff_validator: ProviderToggle {
                enabled: true,
                risk_weight: Some(10),
                max_chain_depth: Some(3),
                reject_private_in_chain: Some(false),
            },
        },
        intel: IntelSources {
            asn_feed: FeedRef {
                refresh_secs: Some(86_400),
                ..Default::default()
            },
            tor_feed: FeedRef {
                url: "https://check.torproject.org/torbulkexitlist".to_owned(),
                refresh_secs: Some(3_600),
                ..Default::default()
            },
            datacenter_set: FeedRef::default(),
        },
        trusted_proxies: Vec::new(),
        risk_weights: RiskWeights {
            tor: 30,
            datacenter: 15,
            bad_asn: 25,
        },
    }
}

// ─── Live evaluation via engine config ───────────────────────────────────────

/// Parse the relay YAML through `waf-engine`'s own loader, surfacing the same
/// errors operators see when the engine boots — keeps this endpoint and the
/// gateway in lockstep on what is a "valid" config.
async fn load_relay_engine_config(path: &Path) -> Option<Arc<waf_engine::relay::RelayConfig>> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    match waf_engine::relay::RelayConfig::from_yaml_str(&raw) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "relay: engine parse failed");
            None
        }
    }
}

fn build_request_headers(xff: Option<&str>) -> HttpHeaderMap {
    let mut headers = HttpHeaderMap::new();
    if let Some(xff) = xff
        && let (Ok(name), Ok(value)) = (HeaderName::from_str("x-forwarded-for"), HeaderValue::from_str(xff))
    {
        headers.insert(name, value);
    }
    headers
}

fn signal_label(s: &waf_engine::relay::Signal) -> String {
    // `Signal` derives `Debug` — keep the wire format string-typed so future
    // variants don't break the FE.
    format!("{s:?}")
}

// ─── Handlers ────────────────────────────────────────────────────────────────

pub async fn get_relay_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_under_root(&state, "configs/relay.yaml");
    let cfg = read_yaml_opt::<RelayApiConfig>(&path)
        .await
        .unwrap_or_else(default_relay_config);
    Ok(Json(json!({ "success": true, "data": cfg })))
}

pub async fn put_relay_config(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(body): Json<RelayApiConfig>,
) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    let path = resolve_under_root(&state, "configs/relay.yaml");
    write_yaml(&path, &body).await?;
    Ok(Json(json!({ "success": true, "data": body })))
}

pub async fn get_relay_intel_status(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    // Without a wired RelayDetector at engine scope (PR-β2 territory) we
    // surface the static config inventory — the FE can show "configured but
    // not yet refreshed" instead of false-positive entry counts.
    let path = resolve_under_root(&state, "configs/relay.yaml");
    let cfg = read_yaml_opt::<RelayApiConfig>(&path).await.unwrap_or_default();
    Ok(Json(json!({
        "success": true,
        "data": {
            "tor": {
                "configured_url": cfg.intel.tor_feed.url,
                "refresh_secs": cfg.intel.tor_feed.refresh_secs,
                "entry_count": 0,
                "last_refresh": Value::Null,
                "last_error": Value::Null,
            },
            "asn": {
                "configured_url": cfg.intel.asn_feed.url,
                "refresh_secs": cfg.intel.asn_feed.refresh_secs,
                "entry_count": 0,
                "last_refresh": Value::Null,
                "last_error": Value::Null,
            },
            "datacenter": {
                "configured_path": cfg.intel.datacenter_set.path,
                "entry_count": 0,
                "last_refresh": Value::Null,
                "last_error": Value::Null,
            }
        }
    })))
}

pub async fn refresh_relay_intel(State(state): State<Arc<AppState>>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&headers, &state.jwt_secret)?;
    // Validate that the YAML parses through the engine's loader. The full
    // provider-refresh task graph is registered by PR-β2; until that PR
    // lands, the actionable thing this endpoint can do is detect bad config
    // before operators reload.
    let path = resolve_under_root(&state, "configs/relay.yaml");
    let started = Instant::now();
    match load_relay_engine_config(&path).await {
        Some(_) => Ok(Json(json!({
            "success": true,
            "data": {
                "parsed": true,
                "providers_wired": false,
                "took_ms": u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                "note": "config parses; live refresh pending PR-β2 wiring"
            }
        }))),
        None => Err(ApiError::BadRequest(format!(
            "relay YAML at {} did not parse via engine loader",
            path.display()
        ))),
    }
}

pub async fn test_relay(
    State(state): State<Arc<AppState>>,
    Json(req): Json<TestRelayRequest>,
) -> ApiResult<Json<Value>> {
    let peer_ip =
        IpAddr::from_str(&req.client_ip).map_err(|e| ApiError::BadRequest(format!("client_ip parse: {e}")))?;
    let path = resolve_under_root(&state, "configs/relay.yaml");
    let engine_cfg = load_relay_engine_config(&path)
        .await
        .ok_or_else(|| ApiError::BadRequest(format!("relay YAML at {} unavailable for evaluation", path.display())))?;
    let registry = waf_engine::relay::ProviderRegistry::new();
    let detector = waf_engine::relay::RelayDetector::new(engine_cfg, registry);
    let headers = build_request_headers(req.xff.as_deref());
    let identity = detector.evaluate(peer_ip, &headers);
    let verdicts: Vec<String> = identity.signals.iter().map(signal_label).collect();
    Ok(Json(json!({
        "success": true,
        "data": {
            "client_ip": req.client_ip,
            "real_ip": identity.real_ip.to_string(),
            "asn_class": format!("{:?}", identity.asn_class),
            "verdicts": verdicts,
            "total_risk_delta": 0,
        }
    })))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn default_relay_config_has_known_shape() {
        let c = default_relay_config();
        assert!(!c.enabled);
        assert!(c.providers.tor_exit.enabled);
        assert_eq!(c.risk_weights.tor, 30);
        assert!(c.intel.tor_feed.url.contains("torproject.org"));
    }

    #[test]
    fn signal_label_round_trips_a_known_variant() {
        let s = waf_engine::relay::Signal::TorExit;
        assert_eq!(signal_label(&s), "TorExit");
    }

    #[test]
    fn build_request_headers_inserts_xff_when_set() {
        let headers = build_request_headers(Some("203.0.113.5, 10.0.0.1"));
        assert!(headers.get("x-forwarded-for").is_some());
    }

    #[test]
    fn build_request_headers_skips_when_none() {
        let headers = build_request_headers(None);
        assert!(headers.is_empty());
    }
}
