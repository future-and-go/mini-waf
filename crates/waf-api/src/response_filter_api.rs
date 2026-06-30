//! Response Filtering admin API (US-1801, gap spec §A2 — FR-033/034/035).
//!
//! Surfaces the three endpoints the admin panel's Response Filtering page
//! (`web/admin-panel/src/pages/response-filtering/index.tsx`) already calls but
//! that previously 404'd:
//!
//! - `POST /api/response-filtering/preview` — run the **global** panel-config
//!   response-filter rules over a supplied body and return the redacted text.
//! - `GET  /api/hosts/{id}/response-filter` — read the per-host filter
//!   (documented defaults when unset).
//! - `PUT  /api/hosts/{id}/response-filter` — validate + persist the per-host
//!   filter under `Host.defense_json.response_filter` (decision 0011).
//!
//! The runtime redaction/scanning engine is reused verbatim from `gateway`
//! (`CompiledScanner`, `CompiledRedactor`) — this module adds only the admin
//! API surface, never new redaction logic.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::connect_info::ConnectInfo;
use axum::http::{HeaderMap, header::AUTHORIZATION};
use axum::{
    Json,
    extract::{Path, State},
};
use bytes::Bytes;
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use gateway::context::BodyScanState;
use gateway::filters::{CompiledRedactor, CompiledScanner, apply_body_scan_chunk, is_json_content_type};
use waf_common::panel_config::WafPanelConfig;
use waf_common::{HostConfig, HostResponseFilter};
use waf_storage::models::UpdateHost;

use crate::auth::validate_access_token;
use crate::error::{ApiError, ApiResult};
use crate::handlers::{host_config_from_row, response_filter_from_defense_json};
use crate::state::AppState;

/// Hard cap on the preview request body. Mirrors the engine's per-response
/// scan budget; a larger body is rejected with `413` rather than scanned.
const PREVIEW_MAX_BODY_BYTES: usize = 1 << 20; // 1 MiB

/// Lower / upper bounds for `body_scan_max_body_bytes` (mirrors the FE input).
const MIN_BODY_SCAN_BYTES: u64 = 1024;
const MAX_BODY_SCAN_BYTES: u64 = 10 * 1024 * 1024;

// ─── POST /api/response-filtering/preview ─────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct PreviewRequest {
    pub body: String,
    #[serde(default)]
    pub content_type: String,
}

/// Preview the **global** response-filter rules over a sample body.
///
/// Reads `WafPanelConfig.response_filtering` from the panel TOML and maps it to
/// a transient `HostConfig`: `block_stack_traces` enables the FR-033 built-in
/// content scanner, and `json_redact_fields` drives the FR-034 JSON field
/// redactor. The scanner catalog is all-or-nothing (no per-category toggle),
/// so any enabled category enables the whole scanner.
///
/// SECURITY: never logs the request body or the result — both may carry
/// secrets the operator is precisely trying to redact.
pub async fn preview_response_filter(
    State(state): State<Arc<AppState>>,
    Json(req): Json<PreviewRequest>,
) -> ApiResult<Json<Value>> {
    if req.body.len() > PREVIEW_MAX_BODY_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "preview body exceeds {PREVIEW_MAX_BODY_BYTES} bytes"
        )));
    }

    let panel = load_panel_config(&state).await?;
    let rf = &panel.response_filtering;

    // Map the global panel-config onto a transient HostConfig for the engine.
    let hc = HostConfig {
        body_scan_enabled: rf.block_stack_traces,
        redact_extra_fields: rf.json_redact_fields.clone(),
        ..HostConfig::default()
    };

    let result = run_preview(&hc, req.body.as_bytes(), &req.content_type);
    Ok(Json(json!({ "success": true, "data": { "result": result } })))
}

/// Run the FR-033 scanner (when enabled) followed by the FR-034 JSON field
/// redactor (JSON content-types only) over `body`, returning the lossy UTF-8
/// rendering of the filtered bytes. Pure, in-process, no network I/O.
fn run_preview(hc: &HostConfig, body: &[u8], content_type: &str) -> String {
    let mut bytes = Bytes::copy_from_slice(body);

    // FR-033: built-in content scanner (stack traces, verbose errors, secrets,
    // internal IPs). Single-chunk + EOS over the supplied plaintext body.
    if hc.body_scan_enabled {
        let scanner = Arc::new(CompiledScanner::build(hc.body_scan_max_body_bytes));
        let mut scan_state = BodyScanState {
            enabled: true,
            ..Default::default()
        };
        let mut slot = Some(bytes);
        apply_body_scan_chunk(&mut scan_state, &scanner, &mut slot, true, "__preview__");
        bytes = slot.unwrap_or_default();
    }

    // FR-034: JSON field redactor — JSON content-types only.
    if is_json_content_type(content_type) {
        let redactor = CompiledRedactor::build(hc);
        if !redactor.is_noop()
            && let Some(redacted) = redactor.redact_bytes(&bytes)
        {
            bytes = Bytes::from(redacted);
        }
    }

    String::from_utf8_lossy(&bytes).into_owned()
}

async fn load_panel_config(state: &AppState) -> Result<WafPanelConfig, ApiError> {
    let path = state.panel_config_path.as_ref().ok_or_else(|| {
        ApiError::BadRequest("panel.config_path is not set in the main TOML ([panel] section).".into())
    })?;
    let raw = tokio::fs::read_to_string(path)
        .await
        .map_err(|e| ApiError::Internal(anyhow::anyhow!("read panel config file: {e}")))?;
    WafPanelConfig::from_toml_str(&raw).map_err(|e| ApiError::BadRequest(format!("{e}")))
}

// ─── GET /api/hosts/{id}/response-filter ──────────────────────────────────────

/// Read the per-host response filter. Returns documented defaults (mirroring
/// `HostConfig::default()`) when the host has no stored override — `200`, never
/// `404` (a missing host id is still `404`).
pub async fn get_host_response_filter(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;

    let rf = response_filter_from_defense_json(host.defense_json.as_ref()).unwrap_or_default();
    Ok(Json(json!({ "success": true, "data": rf })))
}

// ─── PUT /api/hosts/{id}/response-filter ──────────────────────────────────────

/// Validate + persist the per-host response filter under
/// `defense_json.response_filter`, re-register the host config so the proxy
/// honors it, and audit the mutation.
///
/// Fail-safe: validation runs **before** any persistence, so a bad regex can
/// never reach the proxy.
pub async fn put_host_response_filter(
    State(state): State<Arc<AppState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(id): Path<Uuid>,
    Json(req): Json<HostResponseFilter>,
) -> ApiResult<Json<Value>> {
    validate_response_filter(&req)?;

    let old_host = state
        .db
        .get_host(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;

    // Merge the filter into the existing defense_json blob under `response_filter`.
    let mut defense_json = match old_host.defense_json.clone() {
        Some(v) if v.is_object() => v,
        _ => json!({}),
    };
    let rf_value = serde_json::to_value(&req).map_err(|e| ApiError::Internal(anyhow::anyhow!(e)))?;
    if let Some(obj) = defense_json.as_object_mut() {
        obj.insert("response_filter".to_string(), rf_value);
    }

    let updated = state
        .db
        .update_host(
            id,
            UpdateHost {
                defense_json: Some(defense_json),
                ..UpdateHost::default()
            },
        )
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Host {id} not found")))?;

    // Re-register so the running proxy applies the override (mirrors update_host).
    let old_port = u16::try_from(old_host.port).unwrap_or(80);
    state.router.unregister(&old_host.host, old_port);
    let config = host_config_from_row(&updated);
    state.router.register(&config);

    // Audit the config mutation (command owns the side effect).
    let admin_username = bearer_username(&headers, &state.jwt_secret);
    let ip = peer.ip().to_string();
    if let Err(e) = state
        .db
        .create_audit_log(
            admin_username.as_deref(),
            "update_host_response_filter",
            Some("host_response_filter"),
            Some(&id.to_string()),
            Some(json!({ "host_code": updated.code })),
            Some(&ip),
        )
        .await
    {
        tracing::warn!("failed to write audit log for response-filter update: {e}");
    }

    Ok(Json(json!({ "success": true, "data": req })))
}

/// Validate a per-host response filter before persistence (fail-safe).
fn validate_response_filter(rf: &HostResponseFilter) -> Result<(), ApiError> {
    if !(MIN_BODY_SCAN_BYTES..=MAX_BODY_SCAN_BYTES).contains(&rf.body_scan_max_body_bytes) {
        return Err(ApiError::BadRequest(format!(
            "body_scan_max_body_bytes must be between {MIN_BODY_SCAN_BYTES} and {MAX_BODY_SCAN_BYTES}"
        )));
    }
    for p in &rf.internal_patterns {
        regex::Regex::new(p).map_err(|e| ApiError::BadRequest(format!("invalid internal_pattern {p:?}: {e}")))?;
    }
    Ok(())
}

/// Best-effort extraction of the admin username from the bearer token for audit
/// attribution. `require_auth` already guaranteed the token is valid; a parse
/// miss here just yields `None` (the audit row still records action + IP).
fn bearer_username(headers: &HeaderMap, secret: &str) -> Option<String> {
    let token = headers.get(AUTHORIZATION)?.to_str().ok()?.strip_prefix("Bearer ")?;
    validate_access_token(token, secret).ok().map(|c| c.sub)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn panel_hc(block_stack_traces: bool, redact_fields: &[&str]) -> HostConfig {
        HostConfig {
            body_scan_enabled: block_stack_traces,
            redact_extra_fields: redact_fields.iter().map(|s| (*s).to_string()).collect(),
            ..HostConfig::default()
        }
    }

    #[test]
    fn preview_redacts_json_field() {
        let hc = panel_hc(false, &["password"]);
        let out = run_preview(&hc, br#"{"password":"hunter2","user":"alice"}"#, "application/json");
        assert!(out.contains("***REDACTED***"));
        assert!(!out.contains("hunter2"));
        assert!(out.contains("alice"));
    }

    #[test]
    fn preview_masks_stack_trace_when_scanner_enabled() {
        let hc = panel_hc(true, &[]);
        let body = "Traceback (most recent call last):\n  File \"/app/x.py\", line 4, in handler\n";
        let out = run_preview(&hc, body.as_bytes(), "text/plain");
        assert!(
            out.contains("[redacted]"),
            "stack-trace literal should be masked: {out}"
        );
    }

    #[test]
    fn preview_passes_plain_body_through_when_disabled() {
        let hc = panel_hc(false, &[]);
        let out = run_preview(&hc, b"hello world, nothing to see", "text/plain");
        assert_eq!(out, "hello world, nothing to see");
    }

    #[test]
    fn preview_non_json_skips_field_redactor() {
        // json_redact_fields configured, but content-type is not JSON → no redact.
        let hc = panel_hc(false, &["password"]);
        let out = run_preview(&hc, br#"{"password":"hunter2"}"#, "text/html");
        assert!(out.contains("hunter2"));
    }

    #[test]
    fn validate_rejects_bad_regex() {
        let rf = HostResponseFilter {
            internal_patterns: vec!["(".to_string()],
            ..HostResponseFilter::default()
        };
        assert!(validate_response_filter(&rf).is_err());
    }

    #[test]
    fn validate_rejects_out_of_range_bytes() {
        let too_small = HostResponseFilter {
            body_scan_max_body_bytes: 10,
            ..HostResponseFilter::default()
        };
        assert!(validate_response_filter(&too_small).is_err());
        let too_large = HostResponseFilter {
            body_scan_max_body_bytes: MAX_BODY_SCAN_BYTES + 1,
            ..HostResponseFilter::default()
        };
        assert!(validate_response_filter(&too_large).is_err());
    }

    #[test]
    fn validate_accepts_valid_filter() {
        let rf = HostResponseFilter {
            body_scan_enabled: true,
            body_scan_max_body_bytes: 65536,
            internal_patterns: vec![r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}".to_string()],
            header_blocklist: vec!["X-Powered-By".to_string()],
            strip_server_header: true,
        };
        assert!(validate_response_filter(&rf).is_ok());
    }
}
