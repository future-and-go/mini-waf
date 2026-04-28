//! WAF decision → HTTP response helpers used by the proxy filter callbacks.
//!
//! Extracted from `proxy.rs` to keep each file under 200 lines.

use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tracing::warn;

use pingora_proxy::Session;
use waf_common::{WafAction, WafDecision};

/// Write a WAF block/redirect response to `session` and return `Ok(true)` to
/// tell `request_filter` that the response is already sent.
///
/// Returns `Ok(false)` when the decision is `Allow` / `LogOnly`.
pub async fn write_waf_decision(
    session: &mut Session,
    decision: &WafDecision,
    request_ctx: &waf_common::RequestCtx,
    blocked_counter: &AtomicU64,
) -> pingora_core::Result<bool> {
    if !decision.is_allowed() {
        blocked_counter.fetch_add(1, Ordering::Relaxed);
        match &decision.action {
            WafAction::Block { status, body } => {
                let (rule_id, rule_name, phase, detail) = decision
                    .result
                    .as_ref()
                    .map(|r| {
                        (
                            r.rule_id.clone().unwrap_or_default(),
                            r.rule_name.clone(),
                            r.phase.to_string(),
                            r.detail.clone(),
                        )
                    })
                    .unwrap_or_default();
                warn!(
                    rule_id = %rule_id,
                    rule_name = %rule_name,
                    phase = %phase,
                    detail = %detail,
                    method = %request_ctx.method,
                    path = %request_ctx.path,
                    host = %request_ctx.host,
                    ua = %request_ctx.headers.get("user-agent").cloned().unwrap_or_default(),
                    "WAF blocked request",
                );
                let status_code = *status;
                let body_str = body.clone().unwrap_or_else(|| "Access Denied".to_string());
                let response = pingora_http::ResponseHeader::build(status_code, None)?;
                session.write_response_header(Box::new(response), false).await?;
                session.write_response_body(Some(Bytes::from(body_str)), true).await?;
                return Ok(true);
            }
            WafAction::Redirect { url } => {
                let mut response = pingora_http::ResponseHeader::build(302, None)?;
                response.insert_header("location", url.as_str())?;
                session.write_response_header(Box::new(response), true).await?;
                return Ok(true);
            }
            _ => {}
        }
    }
    Ok(false)
}

/// Write a WAF body-inspection block/redirect response and return an error to
/// halt further body streaming (`request_body_filter` must return `Err`).
///
/// Returns `Ok(())` when the decision is `Allow` / `LogOnly`.
pub async fn write_waf_body_decision(
    session: &mut Session,
    decision: &WafDecision,
    request_ctx: &waf_common::RequestCtx,
    blocked_counter: &AtomicU64,
) -> pingora_core::Result<()> {
    if !decision.is_allowed() {
        blocked_counter.fetch_add(1, Ordering::Relaxed);
        match &decision.action {
            WafAction::Block {
                status,
                body: block_body,
            } => {
                warn!(
                    "WAF blocked request (body): ip={} path={} host={}",
                    request_ctx.client_ip, request_ctx.path, request_ctx.host,
                );
                let status_code = *status;
                let body_str = block_body.clone().unwrap_or_else(|| "Access Denied".to_string());
                let response = pingora_http::ResponseHeader::build(status_code, None)?;
                session.write_response_header(Box::new(response), false).await?;
                session.write_response_body(Some(Bytes::from(body_str)), true).await?;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(status_code),
                    "WAF blocked request body",
                ));
            }
            WafAction::Redirect { url } => {
                let mut response = pingora_http::ResponseHeader::build(302, None)?;
                response.insert_header("location", url.as_str())?;
                session.write_response_header(Box::new(response), true).await?;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(302),
                    "WAF redirected request",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}
