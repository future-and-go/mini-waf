//! Risk scoring API — GET/PUT /api/risk/config, GET /api/risk/metrics,
//! GET /api/risk/actors, POST /api/risk/actors/:id/credit|clear.
//!
//! Config source: `configs/risk.yaml` (root key `risk:`). GET/PUT round-trip
//! through `RiskConfig` serde so field names always match what the engine's
//! hot-reload watcher parses. PUT deep-merges the request body over the
//! current file, so sections the admin panel does not edit (seed paths,
//! ingest weights, challenge, thresholds) survive a save.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use waf_engine::risk::config::RiskConfig;

use crate::config_files::{read_yaml_opt, resolve_path, write_yaml};
use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Config helpers ───────────────────────────────────────────────────────────

/// Current `risk:` node from `configs/risk.yaml` as JSON, or the serialized
/// default config when the file is missing or has no `risk:` key.
async fn current_risk_node(path: &std::path::Path) -> Result<Value, ApiError> {
    if let Some(v) = read_yaml_opt(path).await
        && let Some(r) = v.get("risk")
        && !r.is_null()
    {
        return Ok(r.clone());
    }
    serde_json::to_value(RiskConfig::default()).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))
}

/// Deep-merge `patch` over `base`: objects merge recursively, everything else
/// (arrays included) replaces wholesale.
fn deep_merge(base: &mut Value, patch: Value) {
    match (base, patch) {
        (Value::Object(b), Value::Object(p)) => {
            for (k, v) in p {
                deep_merge(b.entry(k).or_insert(Value::Null), v);
            }
        }
        (b, p) => *b = p,
    }
}

/// The store backend is start-time only: the engine's hot-reload keeps the
/// active store when `store.backend` changes. True when the saved config asks
/// for a different backend than the one actually running (including a redis →
/// memory startup fallback), i.e. the operator needs a gateway restart for the
/// saved value to take effect. `active = None` (watcher not started, e.g. unit
/// tests) cannot claim a mismatch.
fn backend_restart_required(requested: &str, active: Option<&str>) -> bool {
    active.is_some_and(|a| a != requested)
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

pub async fn get_risk_config(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/risk.yaml");
    let node = current_risk_node(&path).await?;
    // Round-trip through RiskConfig so the FE always receives the full,
    // defaulted shape even when the file only sets a subset of fields.
    let cfg: RiskConfig = serde_json::from_value(node)
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("configs/risk.yaml does not parse as RiskConfig: {e}")))?;
    let data = serde_json::to_value(&cfg).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    // `active_store_backend` is the backend actually running, which can lag
    // the file (backend edits are start-time only) or differ from it after a
    // redis connect fallback — the operator's downgrade-detection surface.
    Ok(Json(json!({
        "success": true,
        "data": data,
        "active_store_backend": state.engine.risk_store_backend(),
    })))
}

pub async fn put_risk_config(State(state): State<Arc<AppState>>, Json(body): Json<Value>) -> ApiResult<Json<Value>> {
    let path = resolve_path(&state, "configs/risk.yaml");
    let mut merged = current_risk_node(&path).await?;
    deep_merge(&mut merged, body);
    // Validation gate: the merged node must parse as a full RiskConfig, or
    // the file is left untouched. This is exactly what the engine's watcher
    // will parse after the write triggers a hot-reload.
    let cfg: RiskConfig =
        serde_json::from_value(merged).map_err(|e| ApiError::BadRequest(format!("invalid risk config: {e}")))?;
    let data = serde_json::to_value(&cfg).map_err(|e| ApiError::Internal(anyhow::anyhow!("{e}")))?;
    write_yaml(&path, &json!({ "risk": data })).await?;
    let active = state.engine.risk_store_backend();
    let restart_required = backend_restart_required(&cfg.store.backend, active);
    let mut resp = json!({
        "success": true,
        "data": data,
        "restart_required": restart_required,
        "active_store_backend": active,
    });
    if restart_required && let Some(obj) = resp.as_object_mut() {
        obj.insert(
            "message".into(),
            json!(format!(
                "store.backend saved as \"{}\" but the gateway is running the \"{}\" store; \
                 the change takes effect after a gateway restart",
                cfg.store.backend,
                active.unwrap_or("unknown"),
            )),
        );
    }
    Ok(Json(resp))
}

/// Metrics aggregation does not exist yet: `RiskStore` has no query surface
/// for counts or score percentiles. 501 keeps the UI from rendering zero
/// KPIs as if the system were healthy and idle.
pub async fn get_risk_metrics(_: State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    Err(ApiError::NotImplemented(
        "risk metrics are not implemented; the risk store has no aggregation query yet".into(),
    ))
}

#[derive(Deserialize)]
pub struct ActorsQuery {
    pub limit: Option<i64>,
    pub min_score: Option<i64>,
    pub page: Option<i64>,
}

/// Actor enumeration does not exist yet: `RiskStore` exposes only keyed
/// lookups, no listing. 501 keeps the UI from rendering an empty table as
/// "no risky actors" while credit/clear still mutate live per-IP state.
pub async fn list_risk_actors(_: State<Arc<AppState>>, Query(_q): Query<ActorsQuery>) -> ApiResult<Json<Value>> {
    Err(ApiError::NotImplemented(
        "risk actor listing is not implemented; the risk store cannot enumerate actors yet".into(),
    ))
}

/// Actor ids are IP addresses today (the admin panel lists actors by IP).
fn parse_actor_ip(id: &str) -> Result<std::net::IpAddr, ApiError> {
    id.parse()
        .map_err(|_| ApiError::BadRequest(format!("invalid actor id (expected an IP address): {id}")))
}

#[derive(Deserialize)]
pub struct CreditBody {
    pub amount: Option<i16>,
}

const DEFAULT_CREDIT_AMOUNT: i16 = 25;

pub async fn credit_risk_actor(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Json(body): Json<CreditBody>,
) -> ApiResult<Json<Value>> {
    let ip = parse_actor_ip(&id)?;
    let amount = body.amount.unwrap_or(DEFAULT_CREDIT_AMOUNT);
    if !(1..=100).contains(&amount) {
        return Err(ApiError::BadRequest(format!(
            "amount must be between 1 and 100, got {amount}"
        )));
    }
    let score = state.engine.risk_credit_actor(ip, amount).await?;
    Ok(Json(json!({ "success": true, "data": { "id": id, "score": score } })))
}

pub async fn clear_risk_actor(State(state): State<Arc<AppState>>, Path(id): Path<String>) -> ApiResult<Json<Value>> {
    let ip = parse_actor_ip(&id)?;
    let removed = state.engine.risk_clear_actor(ip).await?;
    Ok(Json(
        json!({ "success": true, "data": { "id": id, "removed": removed } }),
    ))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Non-default fields in every section must survive
    /// YAML → deep-merge → `RiskConfig` → YAML, including sections the admin
    /// panel never sends (seed paths, ingest weights, challenge).
    #[test]
    fn put_merge_preserves_unmanaged_sections() {
        let file_yaml = r"
            enabled: true
            ttl_secs: 900
            challenge:
              header_name: X-Custom-Cred
            ingest:
              signal_weights:
                ua_blocklist: 42
            seed:
              tor_exits_path: /etc/waf/tor-exits.txt
              tor_delta: 55
        ";
        let mut node: Value = serde_yaml::from_str(file_yaml).unwrap();

        // Admin panel PUT: subset of fields only.
        let body = json!({
            "enabled": false,
            "gc_interval_secs": 120,
            "canary": { "enabled": true, "paths": ["/trap"], "ban_ttl_secs": 60 },
            "store": { "backend": "redis", "redis": { "url": "redis://10.0.0.1:6379" } }
        });
        deep_merge(&mut node, body);

        let cfg: RiskConfig = serde_json::from_value(node).expect("merged node must parse");
        let out = serde_json::to_value(&cfg).unwrap();

        // PUT fields applied…
        assert_eq!(out["enabled"], json!(false));
        assert_eq!(out["gc_interval_secs"], json!(120));
        assert_eq!(out["canary"]["paths"], json!(["/trap"]));
        assert_eq!(out["store"]["backend"], json!("redis"));
        assert_eq!(out["store"]["redis"]["url"], json!("redis://10.0.0.1:6379"));
        // …file-only fields preserved…
        assert_eq!(out["ttl_secs"], json!(900));
        assert_eq!(out["challenge"]["header_name"], json!("X-Custom-Cred"));
        assert_eq!(out["ingest"]["signal_weights"]["ua_blocklist"], json!(42));
        assert_eq!(out["seed"]["tor_exits_path"], json!("/etc/waf/tor-exits.txt"));
        assert_eq!(out["seed"]["tor_delta"], json!(55));
        // …and untouched sections keep serde defaults.
        assert_eq!(out["store"]["redis"]["key_prefix"], json!("waf:risk:"));

        // The serialized config must reparse — what the watcher will read.
        let reparsed: RiskConfig = serde_json::from_value(out).unwrap();
        assert_eq!(reparsed.ttl_secs, 900);
    }

    #[test]
    fn put_rejects_invalid_merged_config() {
        let mut node = serde_json::to_value(RiskConfig::default()).unwrap();
        deep_merge(&mut node, json!({ "ttl_secs": "not_a_number" }));
        assert!(serde_json::from_value::<RiskConfig>(node).is_err());
    }

    /// PUT changing `store.backend` away from the running store must be
    /// flagged, never silently 200-OK'd; matching or unknown (watcher not
    /// started) backends must not flag.
    #[test]
    fn backend_change_flags_restart_required() {
        // memory → redis via PUT (engine keeps memory until restart); the
        // same input covers the startup-fallback case where the file already
        // said redis but the connect failed and memory is active.
        assert!(backend_restart_required("redis", Some("memory")));
        assert!(backend_restart_required("memory", Some("redis")));
        // No change → no flag.
        assert!(!backend_restart_required("memory", Some("memory")));
        assert!(!backend_restart_required("redis", Some("redis")));
        // Watcher never started (no active store to contradict).
        assert!(!backend_restart_required("redis", None));
    }

    #[test]
    fn deep_merge_replaces_arrays_wholesale() {
        let mut base = json!({ "canary": { "paths": ["/a", "/b"] } });
        deep_merge(&mut base, json!({ "canary": { "paths": ["/c"] } }));
        assert_eq!(base["canary"]["paths"], json!(["/c"]));
    }
}
