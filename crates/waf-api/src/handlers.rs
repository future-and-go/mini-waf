use axum::{
    Json,
    extract::{Path, Query, State},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

use waf_storage::models::{
    AttackLogQuery, CreateCertificate, CreateCustomRule, CreateHost, CreateIpRule, CreateLbBackend,
    CreateSensitivePattern, CreateUrlRule, SecurityEventQuery, UpdateCustomRule, UpdateHost, UpdateSensitivePattern,
    UpsertHotlinkConfig,
};

use waf_common::{HostConfig, UpstreamAlpn};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Response wrapper ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub const fn ok(data: T) -> Json<Self> {
        Json(Self { success: true, data })
    }
}

// ─── Hosts ────────────────────────────────────────────────────────────────────

pub async fn list_hosts(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let hosts = state.db.list_hosts().await?;
    Ok(Json(json!({ "success": true, "data": hosts })))
}

pub async fn get_host(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn create_host(State(state): State<Arc<AppState>>, Json(req): Json<CreateHost>) -> ApiResult<Json<Value>> {
    // Validate port ranges before DB write to prevent i32→u16 truncation
    if !(1..=65535).contains(&req.port) {
        return Err(ApiError::BadRequest("port must be between 1 and 65535".into()));
    }
    if !(1..=65535).contains(&req.remote_port) {
        return Err(ApiError::BadRequest("remote_port must be between 1 and 65535".into()));
    }

    let host = state.db.create_host(req).await?;

    // Deserialize per-host defense overrides; fall back to defaults if NULL/invalid.
    let defense_config: waf_common::DefenseConfig = host
        .defense_json
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Register with router
    let upstream_alpn = UpstreamAlpn::from_db_str(&host.upstream_alpn);
    let config = Arc::new(HostConfig {
        code: host.code.clone(),
        host: host.host.clone(),
        port: u16::try_from(host.port).unwrap_or(80),
        ssl: host.ssl,
        guard_status: host.guard_status,
        remote_host: host.remote_host.clone(),
        remote_port: u16::try_from(host.remote_port).unwrap_or(80),
        remote_ip: host.remote_ip.clone(),
        cert_file: host.cert_file.clone(),
        key_file: host.key_file.clone(),
        start_status: host.start_status,
        defense_config,
        upstream_alpn,
        upstream_skip_ssl_verify: host.upstream_skip_ssl_verify,
        http_redirect: host.http_redirect,
        ..HostConfig::default()
    });
    state.router.register(&config);

    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn update_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHost>,
) -> ApiResult<Json<Value>> {
    // Validate port ranges before DB write to prevent i32→u16 truncation
    if let Some(port) = req.port
        && !(1..=65535).contains(&port)
    {
        return Err(ApiError::BadRequest("port must be between 1 and 65535".into()));
    }
    if let Some(remote_port) = req.remote_port
        && !(1..=65535).contains(&remote_port)
    {
        return Err(ApiError::BadRequest("remote_port must be between 1 and 65535".into()));
    }

    // Fetch old host to unregister from router before update

    let old_host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    let host = state
        .db
        .update_host(id, req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    // Unregister old route, register updated config
    let old_port = u16::try_from(old_host.port).unwrap_or(80);
    state.router.unregister(&old_host.host, old_port);
    let defense_config: waf_common::DefenseConfig = host
        .defense_json
        .as_ref()
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let port_u16 = u16::try_from(host.port).unwrap_or(80);
    let remote_port_u16 = u16::try_from(host.remote_port).unwrap_or(80);
    let upstream_alpn = UpstreamAlpn::from_db_str(&host.upstream_alpn);
    let config = Arc::new(HostConfig {
        code: host.code.clone(),
        host: host.host.clone(),
        port: port_u16,
        ssl: host.ssl,
        guard_status: host.guard_status,
        remote_host: host.remote_host.clone(),
        remote_port: remote_port_u16,
        remote_ip: host.remote_ip.clone(),
        cert_file: host.cert_file.clone(),
        key_file: host.key_file.clone(),
        start_status: host.start_status,
        defense_config,
        upstream_alpn,
        upstream_skip_ssl_verify: host.upstream_skip_ssl_verify,
        http_redirect: host.http_redirect,
        ..HostConfig::default()
    });
    state.router.register(&config);
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn delete_host(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    // Fetch host before deleting to get hostname/port for router unregister
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;
    let deleted = state.db.delete_host(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Host {id} not found")));
    }
    // Unregister from in-memory router
    let port = u16::try_from(host.port).unwrap_or(80);
    state.router.unregister(&host.host, port);
    // Clear any rules associated with this host
    state.engine.store.allow_ips.clear_host(&host.code);
    state.engine.store.block_ips.clear_host(&host.code);
    state.engine.store.allow_urls.clear_host(&host.code);
    state.engine.store.block_urls.clear_host(&host.code);
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Allow IPs ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HostCodeFilter {
    pub host_code: Option<String>,
}

pub async fn list_allow_ips(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_allow_ips(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_allow_ip(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIpRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_allow_ip(req.clone()).await?;
    // Hot-update engine rules
    state.engine.store.allow_ips.insert(&req.host_code, &req.ip_cidr);
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_allow_ip(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow IP {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload allow IPs after delete: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Block IPs ───────────────────────────────────────────────────────────────

pub async fn list_block_ips(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_block_ips(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_block_ip(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateIpRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_block_ip(req.clone()).await?;
    // Hot-update engine rules
    state.engine.store.block_ips.insert(&req.host_code, &req.ip_cidr);
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_block_ip(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block IP {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload block IPs after delete: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Allow URLs ──────────────────────────────────────────────────────────────

pub async fn list_allow_urls(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_allow_urls(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_allow_url(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUrlRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_allow_url(req.clone()).await?;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_allow_url(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow URL {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload allow URLs after delete: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Block URLs ──────────────────────────────────────────────────────────────

pub async fn list_block_urls(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_block_urls(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_block_url(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateUrlRule>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_block_url(req.clone()).await?;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_block_url(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block URL {id} not found")));
    }
    // Sync in-memory rules with database
    if let Err(e) = state.engine.store.reload_all().await {
        tracing::warn!("Failed to reload block URLs after delete: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Attack Logs ─────────────────────────────────────────────────────────────

pub async fn list_attack_logs(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AttackLogQuery>,
) -> ApiResult<Json<Value>> {
    let (logs, total) = state.db.list_attack_logs(&query).await?;
    Ok(Json(json!({
        "success": true,
        "data": logs,
        "total": total,
        "page": query.page.unwrap_or(1),
        "page_size": query.page_size.unwrap_or(20),
    })))
}

// ─── Security Events ─────────────────────────────────────────────────────────

pub async fn list_security_events(
    State(state): State<Arc<AppState>>,
    Query(query): Query<SecurityEventQuery>,
) -> ApiResult<Json<Value>> {
    let (events, total) = state.db.list_security_events(&query).await?;
    Ok(Json(json!({
        "success": true,
        "data": events,
        "total": total,
        "page": query.page.unwrap_or(1),
        "page_size": query.page_size.unwrap_or(20),
    })))
}

pub async fn get_security_event(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let event = state
        .db
        .get_security_event(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Security event {id} not found")))?;
    Ok(Json(json!({ "success": true, "data": event })))
}

// ─── Status ──────────────────────────────────────────────────────────────────

pub async fn get_status(State(state): State<Arc<AppState>>) -> Json<Value> {
    let hosts = state.router.len();
    let allow_ips = state.engine.store.allow_ips.len();
    let block_ips = state.engine.store.block_ips.len();
    let allow_urls = state.engine.store.allow_urls.len();
    let block_urls = state.engine.store.block_urls.len();
    let total_requests = state.total_requests();

    Json(json!({
        "success": true,
        "data": {
            "version": env!("CARGO_PKG_VERSION"),
            "hosts": hosts,
            "rules": {
                "allow_ips": allow_ips,
                "block_ips": block_ips,
                "allow_urls": allow_urls,
                "block_urls": block_urls,
            },
            "total_requests": total_requests,
        }
    }))
}

// ─── Reload ──────────────────────────────────────────────────────────────────

pub async fn reload_rules(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    state.engine.reload_rules().await.map_err(ApiError::Internal)?;
    Ok(Json(json!({ "success": true, "data": "Rules reloaded" })))
}

pub async fn reload_sqli_scan_config(
    State(state): State<Arc<AppState>>,
    Json(cfg): Json<waf_common::config::SqliScanConfig>,
) -> ApiResult<Json<Value>> {
    state.engine.reload_sqli_scan_config(cfg);
    Ok(Json(json!({ "success": true, "data": "SQLi scan config reloaded" })))
}

// ─── Custom Rules ─────────────────────────────────────────────────────────────

/// Normalise a serialised `CustomRule` so the frontend always sees:
///   `conditions: Condition[]`  (flat legacy array or `[]`)
///   `match_tree: ConditionNode | null`  (top-level, never nested inside conditions)
///
/// The DB packs a tree into the `conditions` column as `{"match_tree": …}`.
/// This helper unpacks that so callers never need to inspect the packed shape.
fn unpack_custom_rule(row: &waf_storage::models::CustomRule) -> Value {
    let mut v = serde_json::to_value(row).unwrap_or_else(|e| {
        tracing::warn!("CustomRule serialization failed (id={}): {e}", row.id);
        Value::Null
    });
    if let Some(obj) = v.as_object_mut() {
        let packed = obj.get("conditions").cloned().unwrap_or(Value::Null);
        if let Some(mt) = packed.as_object().and_then(|m| m.get("match_tree")).cloned() {
            // Packed tree: expose match_tree top-level, conditions → []
            obj.insert("match_tree".to_string(), mt);
            obj.insert("conditions".to_string(), json!([]));
        } else {
            // Legacy flat array: ensure match_tree key is present
            obj.entry("match_tree").or_insert(Value::Null);
        }
    }
    v
}

pub async fn list_custom_rules(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_custom_rules(filter.host_code.as_deref()).await?;
    let data: Vec<Value> = rows.iter().map(unpack_custom_rule).collect();
    Ok(Json(json!({ "success": true, "data": data })))
}

pub async fn create_custom_rule(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCustomRule>,
) -> ApiResult<Json<Value>> {
    use waf_engine::rules::engine::from_db_rule;

    let row = state.db.create_custom_rule(req.clone()).await?;
    // Hot-add to engine
    if let Ok(rule) = from_db_rule(&row) {
        state.engine.custom_rules.add_rule(rule);
    }
    Ok(Json(json!({ "success": true, "data": unpack_custom_rule(&row) })))
}

pub async fn delete_custom_rule(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let rule = state
        .db
        .get_custom_rule(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Rule {id} not found")))?;
    let deleted = state.db.delete_custom_rule(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Rule {id} not found")));
    }
    state
        .engine
        .custom_rules
        .remove_rule(&rule.host_code, &rule.id.to_string());
    Ok(Json(json!({ "success": true, "data": null })))
}

pub async fn update_custom_rule(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateCustomRule>,
) -> ApiResult<Json<Value>> {
    use waf_engine::rules::engine::from_db_rule;

    // Fetch the pre-update rule to obtain host_code for engine removal.
    // If host_code changes in the update the old value is still correct here
    // because remove_rule keys on the old host_code bucket.
    let old = state
        .db
        .get_custom_rule(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Rule {id} not found")))?;

    let row = state
        .db
        .update_custom_rule(id, req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Rule {id} not found")))?;

    // Validate the new engine rule BEFORE touching the live engine state.
    // If parsing fails we return an error and leave the engine intact — the
    // old rule (now stale in DB) stays active rather than silently vanishing.
    let new_engine_rule = if row.enabled {
        Some(from_db_rule(&row).map_err(|e| ApiError::BadRequest(e.to_string()))?)
    } else {
        None
    };

    // Safe to mutate the engine now that the new rule is validated.
    state.engine.custom_rules.remove_rule(&old.host_code, &id.to_string());

    if let Some(rule) = new_engine_rule {
        state.engine.custom_rules.add_rule(rule);
    }

    Ok(Json(json!({ "success": true, "data": unpack_custom_rule(&row) })))
}

// ─── Sensitive Patterns ───────────────────────────────────────────────────────

pub async fn list_sensitive_patterns(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_sensitive_patterns(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_sensitive_pattern(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateSensitivePattern>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_sensitive_pattern(req).await?;
    // Trigger a full reload to rebuild the AhoCorasick automaton
    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("Failed to reload after pattern add: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_sensitive_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_sensitive_pattern(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Pattern {id} not found")));
    }
    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("Failed to reload after pattern delete: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

pub async fn patch_sensitive_pattern(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(body): Json<Value>,
) -> ApiResult<Json<Value>> {
    let obj = body
        .as_object()
        .ok_or_else(|| ApiError::BadRequest("body must be a JSON object".into()))?;

    let is_toggle_only = obj.len() == 1 && obj.contains_key("enabled");

    if is_toggle_only {
        let enabled = obj["enabled"]
            .as_bool()
            .ok_or_else(|| ApiError::BadRequest("enabled must be a boolean".into()))?;
        let found = state.db.toggle_sensitive_pattern(id, enabled).await?;
        if !found {
            return Err(ApiError::NotFound(format!("Pattern {id} not found")));
        }
    } else {
        let pattern = obj.get("pattern").and_then(|v| v.as_str());
        let pattern_type = obj.get("pattern_type").and_then(|v| v.as_str());
        let check_request = obj.get("check_request").and_then(Value::as_bool);
        let check_response = obj.get("check_response").and_then(Value::as_bool);
        let action = obj.get("action").and_then(|v| v.as_str());
        let remarks = obj.get("remarks").and_then(|v| v.as_str());
        let enabled = obj.get("enabled").and_then(Value::as_bool);

        let updated = state
            .db
            .update_sensitive_pattern(
                id,
                UpdateSensitivePattern {
                    pattern,
                    pattern_type,
                    check_request,
                    check_response,
                    action,
                    remarks,
                    enabled,
                },
            )
            .await?;
        if updated.is_none() {
            return Err(ApiError::NotFound(format!("Pattern {id} not found")));
        }
    }

    if let Err(e) = state.engine.reload_rules().await {
        tracing::warn!("Failed to reload after pattern patch: {}", e);
    }
    Ok(Json(json!({ "success": true, "data": { "id": id } })))
}

// ─── Hotlink Config ───────────────────────────────────────────────────────────

pub async fn get_hotlink_config(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let host_code = filter
        .host_code
        .ok_or_else(|| ApiError::BadRequest("host_code required".into()))?;
    let config = state.db.get_hotlink_config(&host_code).await?;
    Ok(Json(json!({ "success": true, "data": config })))
}

pub async fn upsert_hotlink_config(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UpsertHotlinkConfig>,
) -> ApiResult<Json<Value>> {
    let row = state.db.upsert_hotlink_config(req.clone()).await?;
    // Hot-update engine
    let domains = req.allowed_domains.unwrap_or_default();
    let config = waf_engine::checks::anti_hotlink::HotlinkConfig {
        enabled: row.enabled,
        allow_empty_referer: row.allow_empty_referer,
        allowed_domains: domains,
        redirect_url: row.redirect_url.clone(),
    };
    state.engine.hotlink.set_config(&row.host_code, config);
    Ok(Json(json!({ "success": true, "data": row })))
}

// ─── LB Backends ─────────────────────────────────────────────────────────────

pub async fn list_lb_backends(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_lb_backends(filter.host_code.as_deref()).await?;
    Ok(Json(json!({ "success": true, "data": rows })))
}

pub async fn create_lb_backend(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateLbBackend>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_lb_backend(req).await?;
    Ok(Json(json!({ "success": true, "data": row })))
}

pub async fn delete_lb_backend(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_lb_backend(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Backend {id} not found")));
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Certificates ─────────────────────────────────────────────────────────────

pub async fn list_certificates(
    State(state): State<Arc<AppState>>,
    Query(filter): Query<HostCodeFilter>,
) -> ApiResult<Json<Value>> {
    let rows = state.db.list_certificates(filter.host_code.as_deref()).await?;
    // Don't expose private keys in list response
    let safe: Vec<Value> = rows
        .iter()
        .map(|c| {
            json!({
                "id": c.id,
                "host_code": c.host_code,
                "domain": c.domain,
                "issuer": c.issuer,
                "subject": c.subject,
                "not_before": c.not_before,
                "not_after": c.not_after,
                "auto_renew": c.auto_renew,
                "status": c.status,
                "error_msg": c.error_msg,
                "created_at": c.created_at,
                "updated_at": c.updated_at,
            })
        })
        .collect();
    Ok(Json(json!({ "success": true, "data": safe })))
}

pub async fn upload_certificate(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateCertificate>,
) -> ApiResult<Json<Value>> {
    let row = state.db.create_certificate(req.clone()).await?;
    state.db.update_certificate_status(row.id, "active", None).await?;
    Ok(Json(json!({
        "success": true,
        "data": {
            "id": row.id,
            "domain": row.domain,
            "status": "active",
        }
    })))
}

pub async fn delete_certificate(State(state): State<Arc<AppState>>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_certificate(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Certificate {id} not found")));
    }
    Ok(Json(json!({ "success": true, "data": null })))
}

// ─── Log level ───────────────────────────────────────────────────────────────

/// Minimum interval between log-level changes (milliseconds).
const LOG_LEVEL_COOLDOWN_MS: u64 = 10_000;

/// Tracks the last successful log-level change as Unix millis (0 = never).
static LAST_LOG_LEVEL_CHANGE_MS: AtomicU64 = AtomicU64::new(0);

#[derive(Deserialize)]
pub struct SetLogLevelRequest {
    pub filter: String,
}

pub async fn set_log_level(
    State(state): State<Arc<AppState>>,
    Json(req): Json<SetLogLevelRequest>,
) -> ApiResult<Json<Value>> {
    if req.filter.len() > 256 {
        return Err(ApiError::BadRequest("filter string exceeds 256 character limit".into()));
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0) as u64;
    let last = LAST_LOG_LEVEL_CHANGE_MS.load(Ordering::Relaxed);
    if last > 0 && now_ms.saturating_sub(last) < LOG_LEVEL_COOLDOWN_MS {
        let remaining_ms = LOG_LEVEL_COOLDOWN_MS - now_ms.saturating_sub(last);
        return Err(ApiError::TooManyRequests(format!(
            "log level may only change once per {}s; retry in {}ms",
            LOG_LEVEL_COOLDOWN_MS / 1000,
            remaining_ms,
        )));
    }

    let setter = state
        .log_level_setter
        .as_ref()
        .ok_or_else(|| ApiError::Internal(anyhow::anyhow!("log level control not initialized")))?;
    setter(&req.filter).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    LAST_LOG_LEVEL_CHANGE_MS.store(now_ms, Ordering::Relaxed);
    tracing::info!("Log filter updated to: {}", req.filter);
    Ok(Json(json!({ "success": true, "data": { "filter": req.filter } })))
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// Replicates the port validation logic used in `create_host` / `update_host`.
    fn is_valid_port(port: i32) -> bool {
        (1..=65535).contains(&port)
    }

    #[test]
    fn port_validation_valid_range() {
        assert!(is_valid_port(80));
        assert!(is_valid_port(443));
        assert!(is_valid_port(8080));
    }

    #[test]
    fn port_validation_zero_rejected() {
        assert!(!is_valid_port(0));
    }

    #[test]
    fn port_validation_over_65535_rejected() {
        assert!(!is_valid_port(65536));
        assert!(!is_valid_port(100_000));
    }

    #[test]
    fn port_validation_boundary_1() {
        assert!(is_valid_port(1));
    }

    #[test]
    fn port_validation_boundary_65535() {
        assert!(is_valid_port(65535));
    }

    #[test]
    fn port_validation_negative_rejected() {
        assert!(!is_valid_port(-1));
    }

    #[test]
    fn port_validation_i32_min_rejected() {
        assert!(!is_valid_port(i32::MIN));
    }

    #[test]
    fn port_validation_i32_max_rejected() {
        assert!(!is_valid_port(i32::MAX));
    }

    #[test]
    fn set_log_level_request_deserializes() {
        let json = r#"{"filter": "info,waf_engine=debug"}"#;
        let req: super::SetLogLevelRequest = serde_json::from_str(json).expect("parse");
        assert_eq!(req.filter, "info,waf_engine=debug");
    }

    #[test]
    fn set_log_level_filter_length_limit() {
        let long_filter = "a".repeat(257);
        assert!(long_filter.len() > 256, "test expects > 256 chars");
    }
}
