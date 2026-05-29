//! Coverage for `proxy_waf_response::{write_waf_decision, write_waf_body_decision}`.
//!
//! Drives a real `pingora_proxy::Session` over a `tokio::io::duplex` pair so
//! the WAF response builders can be exercised end-to-end without booting a
//! real Pingora server.

#![allow(
    deprecated,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::too_many_lines,
    clippy::doc_markdown,
    clippy::ip_constant,
    clippy::items_after_statements
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use pingora_proxy::Session;
use waf_common::tier::Tier;
use waf_common::{DetectionResult, HostConfig, InteropMode, Phase, RequestCtx, WafAction, WafDecision};

use gateway::proxy_waf_response::{write_waf_body_decision, write_waf_decision};

// ── Fixtures ─────────────────────────────────────────────────────────────────

fn make_request_ctx() -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert("user-agent".into(), "test-agent/1.0".into());
    RequestCtx {
        req_id: "req-1".into(),
        client_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        client_port: 1234,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: "/blocked".into(),
        query: String::new(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: Arc::new(HostConfig::default()),
        geo: None,
        tier: Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
    }
}

fn detection_result() -> DetectionResult {
    DetectionResult {
        rule_id: Some("R-1".into()),
        rule_name: "test-rule".into(),
        phase: Phase::Xss,
        detail: "matched".into(),
        rule_action: None,
        action_status: None,
    }
}

/// Build a minimal HTTP/1 GET request bytes that pingora can parse.
fn http1_request_bytes() -> Vec<u8> {
    b"GET /blocked HTTP/1.1\r\nHost: example.com\r\n\r\n".to_vec()
}

/// Drive a session over an in-memory duplex pair. Returns the session plus a
/// background task handle that drains everything the session writes back.
///
/// Use this when the test only needs to assert the function's return value,
/// not the exact bytes on the wire.
async fn session_over_duplex() -> (Session, tokio::task::JoinHandle<Vec<u8>>) {
    let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
    // Pre-write the request from the client end.
    use tokio::io::AsyncWriteExt;
    client_side.write_all(&http1_request_bytes()).await.expect("write req");

    let drain = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut out = Vec::new();
        // Read until EOF or remote drops.
        let _ = client_side.read_to_end(&mut out).await;
        out
    });

    let mut session = Session::new_h1(Box::new(server_side));
    let ok = session.read_request().await.expect("read_request");
    assert!(ok);
    (session, drain)
}

// ── write_waf_decision tests ─────────────────────────────────────────────────

#[tokio::test]
async fn write_waf_decision_returns_false_for_allow() {
    let (mut session, _drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision::allow();

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(!result, "Allow must not short-circuit the request filter");
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn write_waf_decision_returns_false_for_log_only() {
    let (mut session, _drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::LogOnly,
        result: Some(detection_result()),
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(!result, "LogOnly is treated as allowed");
    // is_allowed() is true for LogOnly so the blocked counter should NOT bump.
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn write_waf_decision_block_writes_status_and_body() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision::block(403, Some("Forbidden by WAF".into()), detection_result());

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result, "Block must signal that response was sent");
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session); // close server side so client read_to_end completes
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(
        wire.starts_with("HTTP/1.1 403"),
        "expected 403 status line, got: {wire}"
    );
    assert!(
        wire.contains("Forbidden by WAF"),
        "block body must reach the wire: {wire}"
    );
}

#[tokio::test]
async fn write_waf_decision_block_uses_default_body_when_none() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision::block(401, None, detection_result());

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result);
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(
        wire.starts_with("HTTP/1.1 401"),
        "expected 401 status line, got: {wire}"
    );
    assert!(
        wire.contains("Access Denied"),
        "default body must be Access Denied: {wire}"
    );
}

#[tokio::test]
async fn write_waf_decision_block_without_detection_result_uses_defaults() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    // Hand-built decision: blocked but no DetectionResult — exercises the
    // `unwrap_or_default()` fallback in the warn! arms.
    let decision = WafDecision {
        action: WafAction::Block {
            status: 418,
            body: Some("teapot".into()),
        },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result);
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(wire.starts_with("HTTP/1.1 418"), "wire: {wire}");
    assert!(wire.contains("teapot"), "wire: {wire}");
}

#[tokio::test]
async fn write_waf_decision_redirect_writes_302_with_location() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::Redirect {
            url: "https://safe.example.com/landing".into(),
        },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result, "Redirect must signal that response was sent");
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(wire.starts_with("HTTP/1.1 302"), "expected 302, got: {wire}");
    let lower = wire.to_lowercase();
    assert!(
        lower.contains("location: https://safe.example.com/landing"),
        "wire: {wire}"
    );
}

#[tokio::test]
async fn write_waf_decision_challenge_action_without_ctx_returns_false() {
    let (mut session, _drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    // When challenge_ctx is None, Challenge action falls through as Allow
    // (fail-open for backward compatibility).
    let decision = WafDecision {
        action: WafAction::Challenge,
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(!result, "Challenge without ctx should not short-circuit");
    // Counter is bumped because is_allowed() returns false for Challenge.
    assert_eq!(
        counter.load(Ordering::Relaxed),
        1,
        "counter must still bump for any non-allowed action"
    );
}

// ── write_waf_body_decision tests ────────────────────────────────────────────

#[tokio::test]
async fn write_waf_body_decision_allow_returns_ok() {
    let (mut session, _drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision::allow();

    write_waf_body_decision(&mut session, &decision, &ctx, &counter)
        .await
        .expect("body decision allow");
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn write_waf_body_decision_log_only_returns_ok() {
    let (mut session, _drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::LogOnly,
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    write_waf_body_decision(&mut session, &decision, &ctx, &counter)
        .await
        .expect("body decision log-only");
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn write_waf_body_decision_block_writes_response_and_errors() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision::block(403, Some("blocked-body".into()), detection_result());

    let err = write_waf_body_decision(&mut session, &decision, &ctx, &counter)
        .await
        .expect_err("body block must return Err to halt streaming");
    assert!(err.to_string().contains("WAF blocked request body") || format!("{err:?}").contains("HTTPStatus"));
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(wire.starts_with("HTTP/1.1 403"), "wire: {wire}");
    assert!(wire.contains("blocked-body"), "wire: {wire}");
}

#[tokio::test]
async fn write_waf_body_decision_block_default_body() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::Block {
            status: 451,
            body: None,
        },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    let err = write_waf_body_decision(&mut session, &decision, &ctx, &counter)
        .await
        .expect_err("must error to halt body streaming");
    let _ = err;
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(wire.starts_with("HTTP/1.1 451"), "wire: {wire}");
    assert!(wire.contains("Access Denied"), "default body must surface: {wire}");
}

#[tokio::test]
async fn write_waf_body_decision_redirect_writes_302_and_errors() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::Redirect { url: "/captcha".into() },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    let err = write_waf_body_decision(&mut session, &decision, &ctx, &counter)
        .await
        .expect_err("redirect must error to halt body streaming");
    assert!(format!("{err:?}").contains("HTTPStatus") || err.to_string().contains("WAF redirected request"));
    assert_eq!(counter.load(Ordering::Relaxed), 1);

    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(wire.starts_with("HTTP/1.1 302"), "wire: {wire}");
    let lower = wire.to_lowercase();
    assert!(lower.contains("location: /captcha"), "wire: {wire}");
}

#[tokio::test]
async fn write_waf_body_decision_challenge_returns_ok() {
    let (mut session, _drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    // Challenge action falls through `_ => {}` and returns Ok(()); counter
    // still bumps because the decision is not allowed.
    let decision = WafDecision {
        action: WafAction::Challenge,
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };

    write_waf_body_decision(&mut session, &decision, &ctx, &counter)
        .await
        .expect("challenge falls through to Ok(())");
    assert_eq!(counter.load(Ordering::Relaxed), 1);
}

// ── Phase 2: new WafAction variant tests ────────────────────────────────────

#[tokio::test]
async fn write_waf_decision_rate_limit_writes_429() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::RateLimit {
            status: 429,
            body: Some("rate limited".into()),
        },
        result: Some(detection_result()),
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };
    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result, "RateLimit must signal that response was sent");
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(
        wire.starts_with("HTTP/1.1 429"),
        "expected 429 status line, got: {wire}"
    );
    assert!(
        wire.contains("rate limited"),
        "rate limit body must reach the wire: {wire}"
    );
}

#[tokio::test]
async fn write_waf_decision_timeout_writes_504() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::Timeout { status: 504 },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };
    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result, "Timeout must signal that response was sent");
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(
        wire.starts_with("HTTP/1.1 504"),
        "expected 504 status line, got: {wire}"
    );
}

#[tokio::test]
async fn write_waf_decision_circuit_breaker_writes_503() {
    let (mut session, drain) = session_over_duplex().await;
    let counter = AtomicU64::new(0);
    let ctx = make_request_ctx();
    let decision = WafDecision {
        action: WafAction::CircuitBreaker {
            status: 503,
            body: Some("upstream down".into()),
        },
        result: None,
        risk_score: 0,
        mode: InteropMode::Enforce,
        rule_id: None,
    };
    let result = write_waf_decision(&mut session, &decision, &ctx, &counter, None)
        .await
        .expect("write_waf_decision");
    assert!(result, "CircuitBreaker must signal that response was sent");
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    drop(session);
    let bytes = drain.await.expect("drain task");
    let wire = String::from_utf8_lossy(&bytes);
    assert!(
        wire.starts_with("HTTP/1.1 503"),
        "expected 503 status line, got: {wire}"
    );
    assert!(
        wire.contains("upstream down"),
        "circuit breaker body must reach the wire: {wire}"
    );
}
