//! WAF decision → HTTP response helpers used by the proxy filter callbacks.
//!
//! Extracted from `proxy.rs` to keep each file under 200 lines.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use pingora_proxy::Session;
use waf_common::{RequestCtx, WafAction, WafDecision};
use waf_engine::challenge::{ChallengeContext, PowSolution, PowVerifyResult, verify_pow};
use waf_engine::risk::VerifyOutcome;

use crate::context::ChallengeCtx;

/// Write a WAF block/redirect/challenge response to `session` and return
/// `Ok(true)` to tell `request_filter` that the response is already sent.
///
/// Returns `Ok(false)` when the decision is `Allow` / `LogOnly`.
///
/// # Challenge handling
/// When `challenge_ctx` is `Some` and action is `Challenge`:
/// - Checks for existing valid `__waf_cc` cookie (bypass if valid)
/// - Renders JS Proof-of-Work challenge page if no valid cookie
///
/// When `challenge_ctx` is `None`, Challenge actions are treated as Allow.
pub async fn write_waf_decision(
    session: &mut Session,
    decision: &WafDecision,
    request_ctx: &RequestCtx,
    blocked_counter: &AtomicU64,
    challenge_ctx: Option<&Arc<ChallengeCtx>>,
) -> pingora_core::Result<bool> {
    if !decision.is_enforcement_allowed() {
        blocked_counter.fetch_add(1, Ordering::Relaxed);
        match &decision.action {
            WafAction::Block { status, body }
            | WafAction::RateLimit { status, body }
            | WafAction::CircuitBreaker { status, body } => {
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
                    action = %decision.action.as_contract_str(),
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
            WafAction::Timeout { status } => {
                let response = pingora_http::ResponseHeader::build(*status, None)?;
                session.write_response_header(Box::new(response), false).await?;
                session
                    .write_response_body(Some(Bytes::from("Gateway Timeout")), true)
                    .await?;
                return Ok(true);
            }
            WafAction::Redirect { url } => {
                let mut response = pingora_http::ResponseHeader::build(302, None)?;
                response.insert_header("location", url.as_str())?;
                session.write_response_header(Box::new(response), true).await?;
                return Ok(true);
            }
            WafAction::Challenge => {
                return handle_challenge(session, request_ctx, challenge_ctx).await;
            }
            // Non-enforced actions: pass through to upstream. Explicit so the
            // compiler flags any future WafAction variant that needs handling.
            #[allow(deprecated)]
            WafAction::Allow | WafAction::LogOnly => {}
        }
    }
    Ok(false)
}

/// Build a fingerprint binding string for challenge token verification.
/// Combines IP + JA3/JA4/H2 fingerprints into a stable hash.
fn build_fingerprint_binding(ctx: &RequestCtx) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ctx.client_ip.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

/// Handle `WafAction::Challenge` by checking cookie or rendering challenge page.
async fn handle_challenge(
    session: &mut Session,
    request_ctx: &RequestCtx,
    challenge_ctx: Option<&Arc<ChallengeCtx>>,
) -> pingora_core::Result<bool> {
    let Some(ctx) = challenge_ctx else {
        debug!("Challenge action but no challenge_ctx configured, allowing request");
        return Ok(false);
    };

    // Check for existing valid __waf_cc cookie
    if let Some(cookie_value) = request_ctx.cookies.get("__waf_cc")
        && let Some(solution) = PowSolution::parse_cookie(cookie_value)
    {
        // Use default difficulty for cookie verification (16 bits)
        let difficulty = ctx.difficulty_map.difficulty_for_risk(50);
        if verify_pow(&solution.token, &solution.nonce, difficulty) == PowVerifyResult::Valid {
            // Verify token signature via ChallengeVerifier
            let binding = build_fingerprint_binding(request_ctx);
            let now_ms = chrono::Utc::now().timestamp_millis();
            match ctx.verifier.verify(&solution.token, &binding, now_ms).await {
                VerifyOutcome::Valid { .. } => {
                    debug!(
                        req_id = %request_ctx.req_id,
                        "Challenge credit valid, allowing request"
                    );
                    return Ok(false);
                }
                outcome => {
                    debug!(
                        req_id = %request_ctx.req_id,
                        ?outcome,
                        "Challenge credit invalid, issuing new challenge"
                    );
                }
            }
        }
    }

    // Issue new challenge token
    let binding = build_fingerprint_binding(request_ctx);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = ctx.issuer.issue(&binding, now_ms);

    // Use default difficulty (risk score not available in WafDecision)
    let difficulty = ctx.difficulty_map.difficulty_for_risk(50);

    // Build redirect URL from original request
    let redirect_url = if request_ctx.query.is_empty() {
        request_ctx.path.clone()
    } else {
        format!("{}?{}", request_ctx.path, request_ctx.query)
    };

    // Render challenge page
    let render_ctx = ChallengeContext {
        token,
        difficulty,
        redirect_url,
        branding_title: ctx.config.branding_title.clone(),
        branding_message: ctx.config.branding_message.clone(),
    };

    let challenge_response = ctx.renderer.render(&render_ctx).map_err(|e| {
        pingora_core::Error::explain(
            pingora_core::ErrorType::InternalError,
            format!("Challenge render failed: {e}"),
        )
    })?;

    // Write response with status and headers from renderer
    let mut resp = pingora_http::ResponseHeader::build(challenge_response.status, None)?;
    for (name, value) in challenge_response.headers {
        // insert_header requires 'static names — pass owned String
        resp.insert_header(name, value)?;
    }

    session.write_response_header(Box::new(resp), false).await?;
    session
        .write_response_body(Some(Bytes::from(challenge_response.body)), true)
        .await?;

    info!(
        req_id = %request_ctx.req_id,
        difficulty,
        "Challenge page served"
    );

    Ok(true)
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
    if !decision.is_enforcement_allowed() {
        blocked_counter.fetch_add(1, Ordering::Relaxed);
        match &decision.action {
            WafAction::Block {
                status,
                body: block_body,
            }
            | WafAction::RateLimit {
                status,
                body: block_body,
            }
            | WafAction::CircuitBreaker {
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
            WafAction::Timeout { status } => {
                let status_code = *status;
                let response = pingora_http::ResponseHeader::build(status_code, None)?;
                session.write_response_header(Box::new(response), false).await?;
                session
                    .write_response_body(Some(Bytes::from("Gateway Timeout")), true)
                    .await?;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(status_code),
                    "WAF timeout",
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
            // Challenge is not enforced at the body-inspection stage; Allow /
            // LogOnly pass through. Explicit so new variants must be handled.
            #[allow(deprecated)]
            WafAction::Allow | WafAction::Challenge | WafAction::LogOnly => {}
        }
    }
    Ok(())
}
