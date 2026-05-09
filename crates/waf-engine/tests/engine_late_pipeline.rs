//! Phase 07 — late-pipeline detection branches: sensitive + anti-hotlink.
//!
//! These checks run after the main checker pipeline and the SQLi check, so
//! the test must use payloads that pass through SQLi/XSS/RCE/Bot/Scanner
//! detectors first. Sensitive patterns are loaded via `reload_rules` from
//! the `sensitive_patterns` DB table; hotlink configs from `hotlink_configs`.

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
    let mut ctx = ctx_for(&code, "/api/LOGONLY-SECRET", "9.9.9.30");
    let host_config = Arc::new(HostConfig {
        code: code.clone(),
        host: "late.example.com".into(),
        log_only_mode: true,
        ..HostConfig::default()
    });
    ctx.host_config = host_config;
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::LogOnly),
        "sensitive LogOnly: got {:?}",
        d.action
    );
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
    let mut ctx = ctx_for(&code, "/img/a.png", "9.9.9.31");
    let host_config = Arc::new(HostConfig {
        code: code.clone(),
        host: "late.example.com".into(),
        log_only_mode: true,
        ..HostConfig::default()
    });
    ctx.host_config = host_config;
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        matches!(d.action, WafAction::LogOnly),
        "hotlink LogOnly: got {:?}",
        d.action
    );
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
    // Pre-populate ctx.geo so the log_attack/security_event/audit helpers
    // exercise the `Some(geo)` JSON-builder branches in engine.rs.
    ctx.geo = Some(GeoIpInfo {
        country: "United States".into(),
        province: "CA".into(),
        city: "San Francisco".into(),
        isp: "Cloudflare".into(),
        iso_code: "US".into(),
    });
    let d = fx.engine.inspect(&mut ctx).await;
    assert!(
        !matches!(d.action, WafAction::Allow),
        "blacklisted IP must block; got {:?}",
        d.action
    );
    // Allow background log_attack future to settle.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn owasp_set_enabled_runs_owasp_phase() {
    let fx = start_engine().await;
    let code = seed_host(&fx.db).await;
    fx.engine.reload_rules().await.expect("reload");
    // Enable OWASP at high paranoia to exercise the owasp.check() branch
    // in the engine pipeline. The default request will not match any rule
    // (owasp.check returns None), exercising the no-match path.
    let dc = DefenseConfig {
        owasp_set: true,
        owasp_paranoia: 4,
        ..DefenseConfig::default()
    };
    let host_config = Arc::new(HostConfig {
        code: code.clone(),
        host: "late.example.com".into(),
        defense_config: dc,
        ..HostConfig::default()
    });
    let mut ctx = ctx_for(&code, "/health", "9.9.9.40");
    ctx.host_config = host_config;
    let d = fx.engine.inspect(&mut ctx).await;
    // No assertion on action — outcome depends on builtin rule set.
    // The point is to flip the `owasp_set` branch in the pipeline.
    let _ = d.action;
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
