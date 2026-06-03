//! ModeRegistry → WafEngine wiring tests.
//!
//! Validates that `apply_mode()` in the inspection pipeline correctly
//! resolves per-feature/policy modes from the registry, respects the
//! host_config.log_only_mode floor, and falls back when no registry is set.

#![allow(
    deprecated,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    unused_imports
)]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use common::{make_ctx, start_engine};
use waf_common::{HostConfig, InteropMode, WafAction};
use waf_engine::interop::{ModeRegistry, ModeState};

const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

fn xss_ctx(code: &str, log_only: bool) -> waf_common::RequestCtx {
    let mut c = make_ctx(code, "/search", "10.20.30.40");
    c.host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "mr-test.example.com".into(),
        log_only_mode: log_only,
        ..HostConfig::default()
    });
    c.headers.insert("user-agent".into(), BENIGN_UA.into());
    c.query = "q=<script>alert(1)</script>".into();
    c
}

fn scanner_ctx(code: &str, log_only: bool) -> waf_common::RequestCtx {
    let mut c = make_ctx(code, "/", "10.20.30.41");
    c.host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "mr-test.example.com".into(),
        log_only_mode: log_only,
        ..HostConfig::default()
    });
    c.headers.insert("user-agent".into(), "sqlmap/1.5.7".into());
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_feature_log_only_overrides_enforce() {
    let fx = start_engine().await;
    let mr = ModeRegistry::new();
    mr.set_feature("injection_control", InteropMode::LogOnly);
    fx.engine.set_mode_registry(mr);

    let mut ctx = xss_ctx("test-mr-01", false);
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::Block { .. }),
        "XSS must still record Block action; got {:?}",
        d.action
    );
    assert_eq!(
        d.mode,
        InteropMode::LogOnly,
        "registry feature override must set LogOnly"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn registry_default_enforce_keeps_enforce() {
    let fx = start_engine().await;
    let mr = ModeRegistry::new(); // default Enforce
    fx.engine.set_mode_registry(mr);

    let mut ctx = xss_ctx("test-mr-02", false);
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::Block { .. }),
        "XSS must block; got {:?}",
        d.action
    );
    assert_eq!(
        d.mode,
        InteropMode::Enforce,
        "default Enforce registry + host enforce → Enforce"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn host_config_log_only_floor_wins_over_registry_enforce() {
    let fx = start_engine().await;
    let mr = ModeRegistry::new(); // default Enforce
    fx.engine.set_mode_registry(mr);

    let mut ctx = xss_ctx("test-mr-03", true); // host log_only=true
    let d = fx.engine.inspect(&mut ctx).await;
    assert_eq!(d.mode, InteropMode::LogOnly, "host_config.log_only_mode floor must win");
}

#[tokio::test(flavor = "multi_thread")]
async fn both_log_only_results_in_log_only() {
    let fx = start_engine().await;
    let mr = ModeRegistry::new();
    mr.set_feature("injection_control", InteropMode::LogOnly);
    fx.engine.set_mode_registry(mr);

    let mut ctx = xss_ctx("test-mr-04", true); // host also log_only
    let d = fx.engine.inspect(&mut ctx).await;
    assert_eq!(d.mode, InteropMode::LogOnly, "both sources LogOnly → LogOnly");
}

#[tokio::test(flavor = "multi_thread")]
async fn policy_level_override_to_log_only() {
    let fx = start_engine().await;
    let mr = ModeRegistry::new(); // default Enforce
    mr.set_policy("injection_control", "xss", InteropMode::LogOnly);
    fx.engine.set_mode_registry(mr);

    let mut ctx = xss_ctx("test-mr-05", false);
    let d = fx.engine.inspect(&mut ctx).await;
    assert_eq!(d.mode, InteropMode::LogOnly, "policy-level override must set LogOnly");
}

#[tokio::test(flavor = "multi_thread")]
async fn no_registry_falls_back_to_host_config_log_only() {
    let fx = start_engine().await;
    // Do NOT call set_mode_registry — OnceLock stays empty

    let mut ctx = xss_ctx("test-mr-06", true);
    let d = fx.engine.inspect(&mut ctx).await;
    assert_eq!(
        d.mode,
        InteropMode::LogOnly,
        "no registry → host_config.log_only_mode must still apply"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn no_registry_falls_back_to_host_config_enforce() {
    let fx = start_engine().await;
    // Do NOT call set_mode_registry — OnceLock stays empty

    let mut ctx = xss_ctx("test-mr-06b", false);
    let d = fx.engine.inspect(&mut ctx).await;
    assert_eq!(d.mode, InteropMode::Enforce, "no registry + host enforce → Enforce");
}

#[tokio::test(flavor = "multi_thread")]
async fn default_log_only_with_feature_enforce_inversion() {
    let fx = start_engine().await;
    let mr = ModeRegistry::new();
    mr.set_all(InteropMode::LogOnly);
    mr.set_feature("injection_control", InteropMode::Enforce);
    fx.engine.set_mode_registry(mr);

    // XSS → injection_control → Enforce (feature override)
    let mut xss = xss_ctx("test-mr-07a", false);
    let d_xss = fx.engine.inspect(&mut xss).await;
    assert_eq!(
        d_xss.mode,
        InteropMode::Enforce,
        "injection_control feature override to Enforce must win"
    );

    // Scanner → bot_detection → LogOnly (inherits default)
    let mut scan = scanner_ctx("test-mr-07b", false);
    let d_scan = fx.engine.inspect(&mut scan).await;
    assert_eq!(
        d_scan.mode,
        InteropMode::LogOnly,
        "bot_detection must inherit default LogOnly"
    );
}
