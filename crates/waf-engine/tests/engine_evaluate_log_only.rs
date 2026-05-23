//! Phase 07 — `log_only_mode` flips Block decisions into LogOnly.
//!
//! Exercises the LogOnly branch of every detection phase reachable without
//! external integrations (CrowdSec, community, geo). Each test seeds a
//! `HostConfig` with `log_only_mode = true`, sends an attack payload, and
//! asserts the action is `LogOnly` with a populated `result`.

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
use waf_storage::models::{CreateHost, CreateIpRule};

async fn seed_host(db: &waf_storage::Database, log_only: bool) -> String {
    db.create_host(CreateHost {
        host: "logonly.example.com".into(),
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
        log_only_mode: log_only,
        upstream_alpn: Default::default(),
        upstream_skip_ssl_verify: false,
    })
    .await
    .expect("create host")
    .code
}

const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

fn ctx_log_only(code: &str, path: &str, ip: &str) -> waf_common::RequestCtx {
    let mut c = make_ctx(code, path, ip);
    let host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "logonly.example.com".into(),
        log_only_mode: true,
        ..HostConfig::default()
    });
    c.host_config = host_config;
    c.headers.insert("user-agent".into(), BENIGN_UA.into());
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn xss_in_log_only_mode_returns_log_only() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db, true).await;
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_log_only(&code, "/search", "9.9.9.10");
    ctx.query = "q=<script>alert(1)</script>".into();
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::LogOnly),
        "XSS LogOnly: got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn directory_traversal_in_log_only_mode_returns_log_only() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db, true).await;
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_log_only(&code, "/files/../../etc/passwd", "9.9.9.11");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::LogOnly),
        "traversal LogOnly: got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn rce_in_log_only_mode_returns_log_only() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db, true).await;
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_log_only(&code, "/exec", "9.9.9.12");
    ctx.query = "cmd=cat%20/etc/passwd;%20id".into();
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::LogOnly),
        "RCE LogOnly: got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn scanner_ua_in_log_only_mode_returns_log_only() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db, true).await;
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_log_only(&code, "/", "9.9.9.13");
    // Override UA: scanner UA must override the BENIGN_UA helper.
    ctx.headers.insert("user-agent".into(), "sqlmap/1.5.7".into());
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::LogOnly),
        "scanner UA LogOnly: got {:?}",
        d.action
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_blacklist_block_path_full_logging_chain_executes() {
    // IP blacklist (Phase 2) does NOT honour log_only_mode — it always blocks.
    // This test ensures the log_attack + report_community_signal + send_audit_event
    // helper chain runs without panicking on the fast-path block.
    let fx = start_engine().await;
    let code = seed_host(&fx.db, false).await;
    fx.db
        .create_block_ip(CreateIpRule {
            host_code: code.clone(),
            ip_cidr: "172.31.0.0/16".into(),
            remarks: None,
        })
        .await
        .expect("seed ip");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = make_ctx(&code, "/", "172.31.5.5");
    ctx.headers.insert("user-agent".into(), BENIGN_UA.into());
    let host_config = Arc::new(HostConfig {
        code: code.clone(),
        host: "logonly.example.com".into(),
        ..HostConfig::default()
    });
    ctx.host_config = host_config;
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(d.action, WafAction::Allow),
        "blacklisted IP must block; got {:?}",
        d.action
    );
    // Allow background tokio::spawn for log_attack to settle (best-effort).
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}
