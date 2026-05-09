//! Phase 07 — late-pipeline log-only branches + geo-populated logging path.
//!
//! Splits out from `engine_late_pipeline.rs` to keep individual integration
//! files under the 200-LOC ceiling. Covers sensitive/hotlink LogOnly,
//! IP-blacklist with `ctx.geo` set (engine.rs JSON-builder branches), and
//! OWASP set enabled.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;

use common::{make_ctx, start_engine};
use waf_common::{DefenseConfig, GeoIpInfo, HostConfig, WafAction};
use waf_storage::models::{CreateHost, CreateIpRule, CreateSensitivePattern, UpsertHotlinkConfig};

const BENIGN_UA: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0";

async fn seed_host(db: &waf_storage::Database) -> String {
    db.create_host(CreateHost {
        host: "latex.example.com".into(),
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
    })
    .await
    .expect("create host")
    .code
}

fn ctx_for(code: &str, path: &str, ip: &str) -> waf_common::RequestCtx {
    let mut c = make_ctx(code, path, ip);
    let host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "latex.example.com".into(),
        ..HostConfig::default()
    });
    c.host_config = host_config;
    c.headers.insert("user-agent".into(), BENIGN_UA.into());
    c
}

fn ctx_log_only(code: &str, path: &str, ip: &str) -> waf_common::RequestCtx {
    let mut c = ctx_for(code, path, ip);
    c.host_config = Arc::new(HostConfig {
        code: code.into(),
        host: "latex.example.com".into(),
        log_only_mode: true,
        ..HostConfig::default()
    });
    c
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_pattern_in_log_only_mode_returns_log_only() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_sensitive_pattern(CreateSensitivePattern {
            host_code: code.clone(),
            pattern: "LOGONLY-SECRET".into(),
            pattern_type: Some("word".into()),
            check_request: Some(true),
            check_response: Some(false),
            action: Some("block".into()),
            remarks: None,
        })
        .await
        .expect("seed sensitive");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_log_only(&code, "/api/LOGONLY-SECRET", "9.9.9.30");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(d.action, WafAction::LogOnly), "got {:?}", d.action);
}

#[tokio::test(flavor = "multi_thread")]
async fn hotlink_in_log_only_mode_returns_log_only() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .upsert_hotlink_config(UpsertHotlinkConfig {
            host_code: code.clone(),
            enabled: Some(true),
            allow_empty_referer: Some(false),
            allowed_domains: Some(vec!["allowed.example.com".into()]),
            redirect_url: None,
        })
        .await
        .expect("seed hotlink");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_log_only(&code, "/img/a.png", "9.9.9.31");
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(matches!(d.action, WafAction::LogOnly), "got {:?}", d.action);
}

#[tokio::test(flavor = "multi_thread")]
async fn ip_blacklist_with_geo_populates_log_attack_geo_branch() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.db
        .create_block_ip(CreateIpRule {
            host_code: code.clone(),
            ip_cidr: "203.0.113.0/24".into(),
            remarks: None,
        })
        .await
        .expect("seed ip");
    fx.engine.reload_rules().await.expect("reload");
    let mut ctx = ctx_for(&code, "/", "203.0.113.42");
    // Pre-populate ctx.geo so log_attack/security_event/audit JSON builders
    // exercise the `Some(geo)` branches in engine.rs.
    ctx.geo = Some(GeoIpInfo {
        country: "United States".into(),
        province: "CA".into(),
        city: "San Francisco".into(),
        isp: "Cloudflare".into(),
        iso_code: "US".into(),
    });
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(!matches!(d.action, WafAction::Allow), "got {:?}", d.action);
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn owasp_set_enabled_runs_owasp_phase() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.engine.reload_rules().await.expect("reload");
    let dc = DefenseConfig {
        owasp_set: true,
        owasp_paranoia: 4,
        ..DefenseConfig::default()
    };
    let mut ctx = ctx_for(&code, "/health", "9.9.9.40");
    ctx.host_config = Arc::new(HostConfig {
        code: code.clone(),
        host: "latex.example.com".into(),
        defense_config: dc,
        ..HostConfig::default()
    });
    let d = fx.engine.inspect(&mut ctx).await;
    let _ = d.action;
}
