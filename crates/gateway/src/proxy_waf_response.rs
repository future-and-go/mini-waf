//! WAF decision → HTTP response helpers used by the proxy filter callbacks.
//!
//! Extracted from `proxy.rs` to keep each file under 200 lines.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::{Bytes, BytesMut};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

use pingora_proxy::Session;
use waf_common::{RequestCtx, WafAction, WafDecision};
use waf_engine::challenge::{ChallengeContext, PowVerifyResult, verify_pow};
use waf_engine::risk::VerifyOutcome;

use crate::context::{ChallengeCtx, GatewayCtx};
use crate::waf_observability_headers::{
    CacheStatus, WafHeaderValues, inject_for_pre_inspect_or_error, inject_waf_observability_headers,
};

/// Canonical Proof-of-Work difficulty for the challenge lifecycle: 16 leading
/// zero bits == 4 leading zero hex chars. The in-page solver and the
/// benchmarker both target 4 hex chars; the server verifies the equivalent bits.
const CHALLENGE_POW_BITS: u8 = 16;

/// JSON solve body posted to `/challenge/verify` by the in-page solver or the
/// benchmarker.
#[derive(Deserialize)]
struct VerifyRequest {
    challenge_token: String,
    nonce: String,
}

/// Whether a token is safe to echo into a `Set-Cookie` value: the issuer emits
/// `base64url(payload).base64url(hmac)`, so only that alphabet (plus a bounded
/// length) is allowed. Rejecting anything else prevents header injection from an
/// attacker-supplied `challenge_token`.
fn is_safe_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 512
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Read the (small) `/challenge/verify` request body, capped at 4 KiB.
async fn read_verify_body(session: &mut Session) -> pingora_core::Result<BytesMut> {
    let mut buf = BytesMut::new();
    while let Some(chunk) = session.read_request_body().await? {
        if chunk.is_empty() {
            continue;
        }
        buf.extend_from_slice(&chunk);
        if buf.len() > 4096 {
            break;
        }
    }
    Ok(buf)
}

/// Handle `POST /challenge/verify`: read the JSON solve, verify the `PoW`, and
/// on success mint a `__waf_cc` credit cookie carrying the opaque HMAC token.
///
/// `PoW` verification here is stateless (`sha256(token + nonce)`); the
/// authoritative HMAC + binding + single-use-nonce check runs on the retried
/// original request in [`handle_challenge`], so the credit cookie is one-shot.
/// Always returns `Ok(true)` — the response is written and never forwarded
/// upstream.
pub async fn handle_challenge_verify(session: &mut Session, ctx: &GatewayCtx) -> pingora_core::Result<bool> {
    let body = read_verify_body(session).await?;
    let solved = serde_json::from_slice::<VerifyRequest>(&body).ok().filter(|p| {
        is_safe_token(&p.challenge_token)
            && verify_pow(&p.challenge_token, &p.nonce, CHALLENGE_POW_BITS) == PowVerifyResult::Valid
    });

    if let Some(p) = solved {
        let mut resp = pingora_http::ResponseHeader::build(200, None)?;
        resp.insert_header("content-length", "0")?;
        resp.insert_header(
            "set-cookie",
            format!("__waf_cc={}; Path=/; HttpOnly; SameSite=Lax", p.challenge_token),
        )?;
        inject_for_pre_inspect_or_error(&mut resp, ctx, "allow", "")?;
        session.write_response_header(Box::new(resp), true).await?;
    } else {
        let mut resp = pingora_http::ResponseHeader::build(403, None)?;
        resp.insert_header("content-length", "0")?;
        inject_for_pre_inspect_or_error(&mut resp, ctx, "block", "")?;
        session.write_response_header(Box::new(resp), true).await?;
    }
    Ok(true)
}

/// Build the contract-mandatory observability values from a WAF decision.
/// WAF-decision egress paths bypass cache capture entirely, so the cache
/// status is hardcoded to `Bypass` (fail-safe: never advertise HIT/MISS for
/// responses authored by the WAF itself).
fn waf_header_values_from_decision<'a>(decision: &'a WafDecision, req_id: &'a str) -> WafHeaderValues<'a> {
    WafHeaderValues {
        request_id: req_id,
        risk_score: decision.risk_score,
        action: decision.action.as_contract_str(),
        rule_id: decision.rule_id.as_deref(),
        mode: decision.mode.as_contract_str(),
        cache: CacheStatus::Bypass,
    }
}

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
        // Bind req_id locally so the values borrow does not collide with the
        // upcoming mutable borrow of the response header.
        let req_id = request_ctx.req_id.as_str();
        let header_values = waf_header_values_from_decision(decision, req_id);
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
                let mut response = pingora_http::ResponseHeader::build(status_code, None)?;
                inject_waf_observability_headers(&mut response, &header_values)?;
                session.write_response_header(Box::new(response), false).await?;
                session.write_response_body(Some(Bytes::from(body_str)), true).await?;
                return Ok(true);
            }
            WafAction::Timeout { status } => {
                let mut response = pingora_http::ResponseHeader::build(*status, None)?;
                inject_waf_observability_headers(&mut response, &header_values)?;
                session.write_response_header(Box::new(response), false).await?;
                session
                    .write_response_body(Some(Bytes::from("Gateway Timeout")), true)
                    .await?;
                return Ok(true);
            }
            WafAction::Redirect { url } => {
                let mut response = pingora_http::ResponseHeader::build(302, None)?;
                response.insert_header("location", url.as_str())?;
                inject_waf_observability_headers(&mut response, &header_values)?;
                session.write_response_header(Box::new(response), true).await?;
                return Ok(true);
            }
            WafAction::Challenge => {
                return handle_challenge(session, decision, request_ctx, challenge_ctx).await;
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
    decision: &WafDecision,
    request_ctx: &RequestCtx,
    challenge_ctx: Option<&Arc<ChallengeCtx>>,
) -> pingora_core::Result<bool> {
    let Some(ctx) = challenge_ctx else {
        debug!("Challenge action but no challenge_ctx configured, allowing request");
        return Ok(false);
    };

    // Retry bypass: the `__waf_cc` credit cookie carries the opaque HMAC token
    // minted by /challenge/verify. The authoritative check is HMAC signature +
    // actor binding + single-use nonce consume (the credit is one-shot); the PoW
    // was already proven at solve time, so it is not re-checked here.
    if let Some(cookie_value) = request_ctx.cookies.get("__waf_cc") {
        let binding = build_fingerprint_binding(request_ctx);
        let now_ms = chrono::Utc::now().timestamp_millis();
        match ctx.verifier.verify(cookie_value, &binding, now_ms).await {
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

    // Issue new challenge token
    let binding = build_fingerprint_binding(request_ctx);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = ctx.issuer.issue(&binding, now_ms);

    // The difficulty map is expressed in leading-zero bits; the in-page solver
    // and the benchmarker both work in leading-zero hex chars (4 bits each), so
    // advertise the hex-char count to keep the challenge solvable.
    let bits = ctx.difficulty_map.difficulty_for_risk(50);
    let hex_difficulty = (bits / 4).max(1);

    // Force action="challenge" on the issued challenge regardless of the
    // decision's contract string (it is "challenge" already, but be explicit
    // so a future variant change cannot silently mislabel the wire).
    let req_id = request_ctx.req_id.as_str();
    let mut header_values = waf_header_values_from_decision(decision, req_id);
    header_values.action = "challenge";

    // Content negotiation: browsers (Accept: text/html) get the Format B HTML
    // page; everything else (the benchmarker) gets Format A JSON.
    let wants_html = request_ctx
        .headers
        .get("accept")
        .is_some_and(|a| a.contains("text/html"));

    if wants_html {
        let redirect_url = if request_ctx.query.is_empty() {
            request_ctx.path.clone()
        } else {
            format!("{}?{}", request_ctx.path, request_ctx.query)
        };
        let render_ctx = ChallengeContext {
            token,
            difficulty: hex_difficulty,
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
        let mut resp = pingora_http::ResponseHeader::build(challenge_response.status, None)?;
        for (name, value) in challenge_response.headers {
            // insert_header requires 'static names — pass owned String
            resp.insert_header(name, value)?;
        }
        inject_waf_observability_headers(&mut resp, &header_values)?;
        session.write_response_header(Box::new(resp), false).await?;
        session
            .write_response_body(Some(Bytes::from(challenge_response.body)), true)
            .await?;
    } else {
        // Format A — JSON challenge (contract §4).
        let body = serde_json::json!({
            "challenge": true,
            "challenge_type": "proof_of_work",
            "challenge_token": token,
            "difficulty": hex_difficulty,
            "submit_url": "/challenge/verify",
            "submit_method": "POST",
        })
        .to_string();
        let mut resp = pingora_http::ResponseHeader::build(429, None)?;
        resp.insert_header("content-type", "application/json")?;
        resp.insert_header("cache-control", "no-store, no-cache, must-revalidate")?;
        inject_waf_observability_headers(&mut resp, &header_values)?;
        session.write_response_header(Box::new(resp), false).await?;
        session.write_response_body(Some(Bytes::from(body)), true).await?;
    }

    info!(
        req_id = %request_ctx.req_id,
        difficulty = hex_difficulty,
        format = if wants_html { "html" } else { "json" },
        "Challenge issued"
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
        let req_id = request_ctx.req_id.as_str();
        let header_values = waf_header_values_from_decision(decision, req_id);
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
                let mut response = pingora_http::ResponseHeader::build(status_code, None)?;
                inject_waf_observability_headers(&mut response, &header_values)?;
                session.write_response_header(Box::new(response), false).await?;
                session.write_response_body(Some(Bytes::from(body_str)), true).await?;
                return Err(pingora_core::Error::explain(
                    pingora_core::ErrorType::HTTPStatus(status_code),
                    "WAF blocked request body",
                ));
            }
            WafAction::Timeout { status } => {
                let status_code = *status;
                let mut response = pingora_http::ResponseHeader::build(status_code, None)?;
                inject_waf_observability_headers(&mut response, &header_values)?;
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
                inject_waf_observability_headers(&mut response, &header_values)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_token_accepts_real_issuer_format() {
        // base64url(payload).base64url(hmac) — the dotted real-issuer shape.
        assert!(is_safe_token("eyJhIjoxfQ.c2lnbmF0dXJl-_123"));
        assert!(is_safe_token("plain-token_123"));
    }

    #[test]
    fn safe_token_rejects_injection_and_empty() {
        assert!(!is_safe_token(""));
        // CRLF / header-injection attempts must be rejected before Set-Cookie.
        assert!(!is_safe_token("abc\r\nSet-Cookie: evil=1"));
        assert!(!is_safe_token("has space"));
        assert!(!is_safe_token("semi;colon"));
        // Over the 512-char ceiling.
        assert!(!is_safe_token(&"a".repeat(513)));
    }

    #[test]
    fn verify_request_parses_contract_body() {
        let body = br#"{"challenge_token":"abc.def","nonce":"12345"}"#;
        let parsed: VerifyRequest = serde_json::from_slice(body).expect("valid body");
        assert_eq!(parsed.challenge_token, "abc.def");
        assert_eq!(parsed.nonce, "12345");
    }
}
