//! Phase 07 — late-pipeline detection branches: sensitive + anti-hotlink.
//!
//! These checks run after the main checker pipeline and the SQLi check, so
//! the test must use payloads that pass through SQLi/XSS/RCE/Bot/Scanner
//! detectors first. Sensitive patterns are loaded via `reload_rules` from
//! the `sensitive_patterns` DB table; hotlink configs from `hotlink_configs`.

#![allow(
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
    clippy::approx_constant,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    unused_imports
)]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use common::{make_ctx, start_engine};
use waf_common::{HostConfig, WafAction};
use waf_storage::models::{CreateHost, CreateSensitivePattern, UpsertHotlinkConfig};

const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

async fn seed_host(db: &waf_storage::Database) -> String {
    db.create_host(CreateHost {
        host: "late.example.com".into(),
        port: 80,
        ssl: false,
        guard_status: true,
        remote_host: "127.0.0.1".into(),
        remote_port: 8080,
        remote_ip: None,
        cert_file: None,
        key_file: None,
        remarks: None,
        start_status: true,
        log_only_mode: false,
        upstream_alpn: Default::default(),
        upstream_skip_ssl_verify: false,
    })
    .await
    .expect("create host")
    .code
}

fn ctx_for(code: &str, path: &str, ip: &str) -> waf_common::RequestCtx {
    let mut c = make_ctx(code, path, ip);
    let host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "late.example.com".into(),
        ..HostConfig::default()
    });
    c.host_config = host_config;
    c.headers.insert("user-agent".into(), BENIGN_UA.into());
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_pattern_in_path_blocks_request() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_sensitive_pattern(CreateSensitivePattern {
            host_code: code.clone(),
            pattern: "TOPSECRET-TOKEN".into(),
            pattern_type: Some("word".into()),
            check_request: Some(true),
            check_response: Some(false),
            action: Some("block".into()),
            remarks: None,
        })
        .await
        .expect("seed sensitive");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_for(&code, "/api/TOPSECRET-TOKEN/leak", "9.9.9.20");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(d.action, WafAction::Allow),
        "sensitive data must block; got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hotlink_blocks_when_referer_missing_and_empty_disallowed() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .upsert_hotlink_config(UpsertHotlinkConfig {
            host_code: code.clone(),
            enabled: Some(true),
            allow_empty_referer: Some(false),
            allowed_domains: Some(vec!["example.com".into()]),
            redirect_url: None,
        })
        .await
        .expect("seed hotlink");
    fx.engine.reload_rules().await.expect("reload");
    // No `referer` header on the context → hotlink check fires.
    let mut ctx = ctx_for(&code, "/images/asset.png", "9.9.9.21");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(d.action, WafAction::Allow),
        "missing referer must block; got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn hotlink_allows_when_referer_in_allowlist() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .upsert_hotlink_config(UpsertHotlinkConfig {
            host_code: code.clone(),
            enabled: Some(true),
            allow_empty_referer: Some(false),
            allowed_domains: Some(vec!["example.com".into()]),
            redirect_url: None,
        })
        .await
        .expect("seed hotlink");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_for(&code, "/images/asset.png", "9.9.9.22");
    ctx.headers.insert("referer".into(), "https://example.com/page".into());
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::Allow),
        "allow-listed referer must allow; got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn reload_rules_with_sensitive_and_hotlink_data_succeeds() {
    // Pure smoke test: exercise the full reload_rules() body with seeded
    // sensitive pattern + hotlink config rows, lifting the load-loop
    // coverage in engine.rs::reload_rules.
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_sensitive_pattern(CreateSensitivePattern {
            host_code: code.clone(),
            pattern: "abcd-1234".into(),
            pattern_type: Some("word".into()),
            check_request: Some(true),
            check_response: Some(false),
            action: Some("block".into()),
            remarks: None,
        })
        .await
        .expect("seed pat");
    fx.db
        .upsert_hotlink_config(UpsertHotlinkConfig {
            host_code: code.clone(),
            enabled: Some(false), // disabled — exercise the disabled branch
            allow_empty_referer: Some(true),
            allowed_domains: Some(vec![]),
            redirect_url: Some("/blocked".into()),
        })
        .await
        .expect("seed hotlink");
    fx.engine.reload_rules().await.expect("reload");

    // Disabled hotlink + no sensitive match in request → Allow.
    let mut ctx = ctx_for(&code, "/health", "9.9.9.23");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::Allow),
        "expected Allow; got {:?}",
        d.action
    );
}
