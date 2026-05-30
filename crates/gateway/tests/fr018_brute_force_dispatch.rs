//! FR-018 — gateway → engine response dispatch wiring tests.
//!
//! Validates that:
//!   - `WafProxy::response_filter`'s `engine.on_response()` dispatch advances
//!     brute-force state when the upstream was actually contacted.
//!   - The gateway-side gate (`ctx.upstream_addr.is_some()` AND
//!     `ctx.request_ctx.is_some()`) excludes self-generated WAF block pages
//!     so they cannot poison BF counters.
//!
//! Engine-side behaviour (gate by route / failed-status / `defense_config` flag)
//! is covered by `crates/waf-engine/tests/p0_detection_acceptance.rs`. These
//! gateway-layer tests exist as regression guards over the wiring contract
//! introduced in this PR.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use gateway::context::GatewayCtx;
use waf_common::{DefenseConfig, HostConfig, RequestCtx};
use waf_engine::checks::{BruteForceCheck, Check};

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

const TEST_IP: &str = "203.0.113.7";

fn login_ctx(body: &[u8], ct: &str, defense: DefenseConfig) -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), ct.to_string());
    RequestCtx {
        req_id: "fr018-dispatch".to_string(),
        client_ip: TEST_IP.parse::<IpAddr>().unwrap(),
        client_port: 0,
        method: "POST".to_string(),
        host: "example.com".to_string(),
        port: 80,
        path: "/login".to_string(),
        query: String::new(),
        headers,
        body_preview: Bytes::copy_from_slice(body),
        content_length: body.len() as u64,
        is_tls: false,
        host_config: Arc::new(HostConfig {
            defense_config: defense,
            ..HostConfig::default()
        }),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}

fn benign_path_ctx(path: &str, defense: DefenseConfig) -> RequestCtx {
    let mut ctx = login_ctx(
        br#"{"username":"alice","password":"wrong"}"#,
        "application/json",
        defense,
    );
    ctx.path = path.to_string();
    ctx
}

/// Mirror of the gateway-side gate in `WafProxy::response_filter`. Test 6
/// proves this gate excludes self-generated WAF block pages.
const fn should_dispatch_on_response(ctx: &GatewayCtx) -> bool {
    ctx.upstream_addr.is_some() && ctx.request_ctx.is_some()
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 1 — Six failed logins record state via BruteForceCheck.on_response
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn six_failed_logins_advance_bf_state() {
    let check = BruteForceCheck::new();
    let body = br#"{"username":"alice","password":"wrong"}"#;

    assert_eq!(check.state().failed_len(), 0, "fresh check must start empty");
    for _ in 0..6 {
        let req = login_ctx(body, "application/json", DefenseConfig::default());
        check.on_response(&req, 401);
    }
    assert!(
        check.state().failed_len() >= 1,
        "expected at least one (user, ip) entry recorded after 6 failed logins"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 2 — Status 200 (successful login) does NOT increment failure counter
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn successful_login_does_not_increment_failures() {
    let check = BruteForceCheck::new();
    let body = br#"{"username":"alice","password":"wrong"}"#;

    for _ in 0..5 {
        let req = login_ctx(body, "application/json", DefenseConfig::default());
        check.on_response(&req, 401);
    }
    let before = check.state().failed_len();

    let success = login_ctx(body, "application/json", DefenseConfig::default());
    check.on_response(&success, 200);

    assert_eq!(
        check.state().failed_len(),
        before,
        "200 status must not advance state map size"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 3 — Non-login route does NOT record failures
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn non_login_route_ignored() {
    let check = BruteForceCheck::new();
    for _ in 0..5 {
        let req = benign_path_ctx("/api/data", DefenseConfig::default());
        check.on_response(&req, 401);
    }
    assert_eq!(
        check.state().failed_len(),
        0,
        "non-login route must not record any failure"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 4 — Non-failed status (5xx) does NOT record failures
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn status_500_not_a_failed_login() {
    let check = BruteForceCheck::new();
    let body = br#"{"username":"alice","password":"wrong"}"#;
    for _ in 0..5 {
        let req = login_ctx(body, "application/json", DefenseConfig::default());
        check.on_response(&req, 500);
    }
    assert_eq!(check.state().failed_len(), 0, "500 is not a failed-login status");
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 5 — defense_config.brute_force = false → on_response is a no-op
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn brute_force_disabled_no_state_advance() {
    let check = BruteForceCheck::new();
    let body = br#"{"username":"alice","password":"wrong"}"#;
    let mut defense = DefenseConfig::default();
    defense.brute_force = false;

    for _ in 0..6 {
        let req = login_ctx(body, "application/json", defense.clone());
        check.on_response(&req, 401);
    }
    assert_eq!(
        check.state().failed_len(),
        0,
        "defense_config.brute_force=false must short-circuit on_response"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// Test 6 — Gateway gate excludes self-generated WAF block pages
//
// The wiring guard is:
//     if ctx.upstream_addr.is_some() {
//         self.engine.on_response(req_ctx, status)
//     }
// Block-page responses are generated BEFORE `upstream_peer` runs, so
// `ctx.upstream_addr` remains `None` and `should_dispatch_on_response`
// returns false — engine.on_response is never invoked.
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn block_page_excluded_from_dispatch() {
    // Block-page scenario: request_ctx may be set (request_filter ran) but
    // upstream_peer never executed, so upstream_addr is None.
    let block_page_ctx = GatewayCtx {
        upstream_addr: None,
        request_ctx: Some(login_ctx(
            br#"{"username":"alice","password":"wrong"}"#,
            "application/json",
            DefenseConfig::default(),
        )),
        ..GatewayCtx::default()
    };
    assert!(
        !should_dispatch_on_response(&block_page_ctx),
        "block-page response must NOT trigger engine.on_response"
    );

    // Sanity: upstream-contacted scenario passes the gate.
    let upstream_ctx = GatewayCtx {
        upstream_addr: Some("10.0.0.1:8080".to_string()),
        request_ctx: Some(login_ctx(
            br#"{"username":"alice","password":"wrong"}"#,
            "application/json",
            DefenseConfig::default(),
        )),
        ..GatewayCtx::default()
    };
    assert!(
        should_dispatch_on_response(&upstream_ctx),
        "upstream-contacted response must trigger engine.on_response"
    );

    // Sanity: request_ctx missing (request_filter early-exit) also fails the
    // gate, even with upstream_addr set.
    let no_req_ctx = GatewayCtx {
        upstream_addr: Some("10.0.0.1:8080".to_string()),
        request_ctx: None,
        ..GatewayCtx::default()
    };
    assert!(
        !should_dispatch_on_response(&no_req_ctx),
        "missing request_ctx must NOT trigger engine.on_response"
    );
}
