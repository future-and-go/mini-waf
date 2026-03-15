use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::Arc;
use uuid::Uuid;

use waf_storage::models::{
    AttackLogQuery, CreateHost, CreateIpRule, CreateUrlRule, UpdateHost,
};

use crate::error::{ApiError, ApiResult};
use crate::state::AppState;

// ─── Response wrapper ─────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: T,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Json<Self> {
        Json(Self { success: true, data })
    }
}

// ─── Hosts ────────────────────────────────────────────────────────────────────

pub async fn list_hosts(State(state): State<Arc<AppState>>) -> ApiResult<Json<Value>> {
    let hosts = state.db.list_hosts().await?;
    Ok(Json(json!({ "success": true, "data": hosts })))
}

pub async fn get_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {} not found", id)))?;
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn create_host(
    State(state): State<Arc<AppState>>,
    Json(req): Json<CreateHost>,
) -> ApiResult<Json<Value>> {
    let host = state.db.create_host(req).await?;

    // Register with router
    use waf_common::HostConfig;
    let config = Arc::new(HostConfig {
        code: host.code.clone(),
        host: host.host.clone(),
        port: host.port as u16,
        ssl: host.ssl,
        guard_status: host.guard_status,
        remote_host: host.remote_host.clone(),
        remote_port: host.remote_port as u16,
        remote_ip: host.remote_ip.clone(),
        cert_file: host.cert_file.clone(),
        key_file: host.key_file.clone(),
        start_status: host.start_status,
        ..HostConfig::default()
    });
    state.router.register(config);

    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn update_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateHost>,
) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .update_host(id, req)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {} not found", id)))?;
    Ok(Json(json!({ "success": true, "data": host })))
}

pub async fn delete_host(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_host(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Host {} not found", id)));
    }
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

pub async fn delete_allow_ip(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow IP {} not found", id)));
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

pub async fn delete_block_ip(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_ip(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block IP {} not found", id)));
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

pub async fn delete_allow_url(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_allow_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Allow URL {} not found", id)));
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

pub async fn delete_block_url(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let deleted = state.db.delete_block_url(id).await?;
    if !deleted {
        return Err(ApiError::NotFound(format!("Block URL {} not found", id)));
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
    state
        .engine
        .reload_rules()
        .await
        .map_err(|e| ApiError::Internal(e))?;
    Ok(Json(json!({ "success": true, "data": "Rules reloaded" })))
}
