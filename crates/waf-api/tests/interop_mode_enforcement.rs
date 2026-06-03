// Integration tests: set_profile API → ModeRegistry → engine.inspect → WafDecision.mode
//
// Validates end-to-end propagation: HTTP set_profile calls update the shared
// ModeRegistry, which engine.inspect reads via apply_mode() to produce the
// correct InteropMode on WafDecision. Complements waf-engine's
// engine_mode_registry.rs (unit-level) with full HTTP-to-engine integration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::doc_markdown,
    clippy::redundant_clone,
    clippy::field_reassign_with_default
)]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use common::{client, start_test_server, url_for};
use reqwest::StatusCode;
use serde_json::{Value, json};
use waf_common::{HostConfig, InteropMode, RequestCtx, WafAction};

const SECRET_HEADER: &str = "x-benchmark-secret";
const VALID_SECRET: &str = "waf-hackathon-2026-ctrl";
const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

// ── HTTP helpers ────────────────────────────────────────────────────────────

fn ctrl_url(s: &common::TestServer, path: &str) -> String {
    url_for(s.addr, &format!("/__waf_control{path}"))
}

async fn post_set_profile(s: &common::TestServer, body: Value) -> (StatusCode, Value) {
    let resp = client()
        .post(ctrl_url(s, "/set_profile"))
        .header(SECRET_HEADER, VALID_SECRET)
        .json(&body)
        .send()
        .await
        .expect("set_profile send");
    let status = resp.status();
    let body: Value = resp.json().await.expect("set_profile json");
    (status, body)
}

async fn post_reset(s: &common::TestServer) -> Value {
    client()
        .post(ctrl_url(s, "/reset_state"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("reset send")
        .json()
        .await
        .expect("reset json")
}

async fn get_capabilities(s: &common::TestServer) -> Value {
    client()
        .get(ctrl_url(s, "/capabilities"))
        .header(SECRET_HEADER, VALID_SECRET)
        .send()
        .await
        .expect("capabilities send")
        .json()
        .await
        .expect("capabilities json")
}

// ── Request context builders ────────────────────────────────────────────────

/// XSS payload → triggers injection_control/xss detection.
fn xss_ctx(code: &str) -> RequestCtx {
    let mut ctx = RequestCtx::default();
    ctx.req_id = format!("interop-xss-{code}");
    ctx.client_ip = "10.20.30.40".parse().unwrap();
    ctx.method = "GET".into();
    ctx.host = "interop-test.example.com".into();
    ctx.port = 80;
    ctx.path = "/search".into();
    ctx.query = "q=<script>alert(1)</script>".into();
    ctx.host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "interop-test.example.com".into(),
        ..HostConfig::default()
    });
    ctx.headers.insert("user-agent".into(), BENIGN_UA.into());
    ctx
}

/// Scanner user-agent → triggers bot_detection/scanner detection.
fn scanner_ctx(code: &str) -> RequestCtx {
    let mut ctx = RequestCtx::default();
    ctx.req_id = format!("interop-scanner-{code}");
    ctx.client_ip = "10.20.30.41".parse().unwrap();
    ctx.method = "GET".into();
    ctx.host = "interop-test.example.com".into();
    ctx.port = 80;
    ctx.path = "/".into();
    ctx.host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "interop-test.example.com".into(),
        ..HostConfig::default()
    });
    ctx.headers.insert("user-agent".into(), "sqlmap/1.5.7".into());
    ctx
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn set_profile_all_log_only_affects_engine() {
    let s = start_test_server().await;

    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "all",
            "mode": "log_only"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut ctx = xss_ctx("all-01");
    let d = s.state.engine.inspect(&mut ctx).await;

    assert!(
        matches!(d.action, WafAction::Block { .. }),
        "XSS must record Block action; got {:?}",
        d.action
    );
    assert_eq!(
        d.mode,
        InteropMode::LogOnly,
        "scope=all log_only must propagate to engine decision"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn set_profile_feature_log_only_selective() {
    let s = start_test_server().await;

    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "features",
            "features": ["injection_control"],
            "mode": "log_only"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // XSS → injection_control → LogOnly (override active)
    let mut xss = xss_ctx("feat-01a");
    let d_xss = s.state.engine.inspect(&mut xss).await;
    assert!(matches!(d_xss.action, WafAction::Block { .. }));
    assert_eq!(
        d_xss.mode,
        InteropMode::LogOnly,
        "injection_control feature must be LogOnly"
    );

    // Scanner → bot_detection → Enforce (no override)
    let mut scan = scanner_ctx("feat-01b");
    let d_scan = s.state.engine.inspect(&mut scan).await;
    assert!(
        matches!(d_scan.action, WafAction::Block { .. }),
        "scanner must still Block; got {:?}",
        d_scan.action
    );
    assert_eq!(
        d_scan.mode,
        InteropMode::Enforce,
        "bot_detection must remain Enforce (not overridden)"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn set_profile_policy_log_only_granular() {
    let s = start_test_server().await;

    // Set only the xss policy within injection_control to log_only
    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "policies",
            "feature": "injection_control",
            "policies": ["xss"],
            "mode": "log_only"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // XSS → injection_control/xss → LogOnly (policy override)
    let mut xss = xss_ctx("pol-01a");
    let d_xss = s.state.engine.inspect(&mut xss).await;
    assert_eq!(
        d_xss.mode,
        InteropMode::LogOnly,
        "injection_control.xss policy must be LogOnly"
    );

    // Scanner → bot_detection/scanner → Enforce (different feature entirely)
    let mut scan = scanner_ctx("pol-01b");
    let d_scan = s.state.engine.inspect(&mut scan).await;
    assert_eq!(
        d_scan.mode,
        InteropMode::Enforce,
        "bot_detection.scanner must remain Enforce"
    );

    // Verify capabilities shows only the targeted policy override
    let caps = get_capabilities(&s).await;
    let overrides = &caps["active"]["overrides"];
    assert_eq!(overrides["injection_control.xss"], "log_only");
    assert!(
        overrides.get("injection_control").is_none(),
        "feature-level override must not exist; only policy-level"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reset_state_clears_mode_overrides() {
    let s = start_test_server().await;

    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "features",
            "features": ["injection_control"],
            "mode": "log_only"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Verify log_only is active
    let mut ctx1 = xss_ctx("reset-01a");
    let d1 = s.state.engine.inspect(&mut ctx1).await;
    assert_eq!(d1.mode, InteropMode::LogOnly, "pre-reset: should be LogOnly");

    // Reset all state
    let reset_resp = post_reset(&s).await;
    assert_eq!(reset_resp["ok"], true);

    // Engine must revert to Enforce
    let mut ctx2 = xss_ctx("reset-01b");
    let d2 = s.state.engine.inspect(&mut ctx2).await;
    assert_eq!(
        d2.mode,
        InteropMode::Enforce,
        "post-reset: engine must revert to Enforce"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn set_profile_enforce_overrides_previous_log_only() {
    let s = start_test_server().await;

    // Step 1: set to log_only
    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "features",
            "features": ["injection_control"],
            "mode": "log_only"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut ctx1 = xss_ctx("enforce-01a");
    let d1 = s.state.engine.inspect(&mut ctx1).await;
    assert_eq!(d1.mode, InteropMode::LogOnly);

    // Step 2: switch back to enforce
    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "features",
            "features": ["injection_control"],
            "mode": "enforce"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let mut ctx2 = xss_ctx("enforce-01b");
    let d2 = s.state.engine.inspect(&mut ctx2).await;
    assert_eq!(d2.mode, InteropMode::Enforce, "enforce must override previous log_only");
}

#[tokio::test(flavor = "multi_thread")]
async fn capabilities_snapshot_reflects_mode() {
    let s = start_test_server().await;

    // Default: Enforce, no overrides
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "enforce");
    assert!(
        caps["active"]["overrides"].as_object().unwrap().is_empty(),
        "default state must have no overrides"
    );

    // Set injection_control to log_only
    let (status, _) = post_set_profile(
        &s,
        json!({
            "scope": "features",
            "features": ["injection_control"],
            "mode": "log_only"
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Capabilities must reflect the override
    let caps = get_capabilities(&s).await;
    assert_eq!(caps["active"]["default_mode"], "enforce");
    assert_eq!(
        caps["active"]["overrides"]["injection_control"], "log_only",
        "capabilities must show injection_control as log_only"
    );
}
