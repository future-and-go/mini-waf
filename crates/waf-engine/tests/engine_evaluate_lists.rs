//! Phase 07 — IP/URL allow/block lists drive `inspect()` decisions.

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
use waf_storage::models::{CreateHost, CreateIpRule, CreateUrlRule};

async fn seed_host(db: &waf_storage::Database) -> String {
    let host = db
        .create_host(CreateHost {
            host: "lists.example.com".into(),
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
            upstream_alpn: "h2h1".to_string(),
            upstream_skip_ssl_verify: false,
            defense_json: None,
        })
        .await
        .expect("create host");
    host.code
}

const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

fn ctx_for(code: &str, path: &str, ip: &str) -> waf_common::RequestCtx {
    let mut c = make_ctx(code, path, ip);
    let host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "lists.example.com".into(),
        ..HostConfig::default()
    });
    c.host_config = host_config;
    c.headers.insert("user-agent".into(), BENIGN_UA.into());
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_blacklist_blocks_request() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_block_ip(CreateIpRule {
            host_code: code.clone(),
            ip_cidr: "192.168.55.0/24".into(),
            remarks: None,
        })
        .await
        .expect("seed block ip");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_for(&code, "/", "192.168.55.7");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(!matches!(d.action, WafAction::Allow), "blacklisted IP must be blocked");
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_whitelist_bypasses_attack_check() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_allow_ip(CreateIpRule {
            host_code: code.clone(),
            ip_cidr: "203.0.113.7/32".into(),
            remarks: None,
        })
        .await
        .expect("seed allow ip");
    fx.engine.reload_rules().await.expect("reload");

    // SQLi-shaped payload + whitelisted IP → Allow.
    let mut ctx = ctx_for(&code, "/products", "203.0.113.7");
    ctx.query = "id=1' OR '1'='1".into();
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Allow), "whitelisted IP must bypass");
}

#[tokio::test(flavor = "multi_thread")]
async fn url_blacklist_blocks_path() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_block_url(CreateUrlRule {
            host_code: code.clone(),
            url_pattern: "/admin".into(),
            match_type: "prefix".into(),
            remarks: None,
        })
        .await
        .expect("seed block url");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_for(&code, "/admin/users", "9.9.9.9");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(!matches!(d.action, WafAction::Allow), "blacklisted URL must block");
}

#[tokio::test(flavor = "multi_thread")]
async fn url_whitelist_short_circuits_to_allow() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_allow_url(CreateUrlRule {
            host_code: code.clone(),
            url_pattern: "/healthz".into(),
            match_type: "exact".into(),
            remarks: None,
        })
        .await
        .expect("seed allow url");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_for(&code, "/healthz", "9.9.9.9");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(d.action, WafAction::Allow), "whitelisted URL must allow");
}

#[tokio::test(flavor = "multi_thread")]
async fn host_specific_reload_clears_stale_rules() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    let r = fx
        .db
        .create_block_ip(CreateIpRule {
            host_code: code.clone(),
            ip_cidr: "10.0.0.1/32".into(),
            remarks: None,
        })
        .await
        .expect("seed");
    fx.engine.reload_rules().await.expect("reload-1");
    let mut ctx = ctx_for(&code, "/", "10.0.0.1");
    assert!(!matches!(fx.engine.inspect(&mut ctx).await.action, WafAction::Allow));

    // Delete the rule and reload-host (atomic-swap path).
    fx.db.delete_block_ip(r.id).await.expect("delete");
    fx.engine.store.reload_host(&code).await.expect("reload host");
    let mut ctx2 = ctx_for(&code, "/", "10.0.0.1");
    assert!(matches!(fx.engine.inspect(&mut ctx2).await.action, WafAction::Allow));
}
