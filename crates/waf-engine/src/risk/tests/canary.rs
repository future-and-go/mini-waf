//! FR-028 Canary Honeypot integration tests.
//!
//! Tests verify:
//! - Canary path triggers score=100 and Block decision
//! - Pin survives decay (`pinned_until_ms` floors score)
//! - Pin expires after TTL
//! - Hot-reload of canary path list
//! - IP added to dynamic ban table

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;

use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, TierPolicy};
use waf_common::{HostConfig, RequestCtx, WafAction};

use arc_swap::ArcSwap as ArcSwapSeed;
use ip_network::IpNetwork;

use crate::checks::ddos::DynamicBanTable;
use crate::risk::canary::CanaryLayer;
use crate::risk::config::{CanaryConfig, RiskConfig};
use crate::risk::scorer::Scorer;
use crate::risk::seed::{SeedDeltas, SeedLayer, SeedTablesBuilder};
use crate::risk::store::MemoryRiskStore;

fn make_ctx(path: &str) -> RequestCtx {
    RequestCtx {
        req_id: "test-canary".to_string(),
        client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 443,
        path: path.to_string(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: bytes::Bytes::new(),
        content_length: 0,
        is_tls: true,
        host_config: Arc::new(HostConfig {
            code: "test".to_string(),
            host: "example.com".to_string(),
            port: 443,
            ssl: true,
            guard_status: true,
            remote_host: "backend".to_string(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: vec![],
            is_enable_load_balance: false,
            load_balance_strategy: waf_common::LoadBalanceStrategy::RoundRobin,
            defense_config: waf_common::DefenseConfig::default(),
            log_only_mode: false,
            block_page_template: None,
            preserve_host: true,
            strip_server_header: false,
            header_blocklist: vec![],
            internal_patterns: vec![],
            mask_token: "[REDACTED]".to_string(),
            body_mask_max_bytes: 1_000_000,
            ..Default::default()
        }),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: Arc::new(TierPolicy {
            fail_mode: FailMode::Open,
            ddos_threshold_rps: 1000,
            cache_policy: CachePolicy::NoCache,
            risk_thresholds: RiskThresholds {
                allow: 30,
                challenge: 70,
                block: 90,
            },
        }),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}

fn make_scorer_with_canary(
    canary_paths: Vec<String>,
    ban_ttl_secs: u32,
) -> (Scorer<MemoryRiskStore>, Arc<DynamicBanTable>) {
    let store = Arc::new(MemoryRiskStore::new());
    let ban_table = Arc::new(DynamicBanTable::new());

    let cfg = RiskConfig {
        enabled: true,
        canary: CanaryConfig {
            enabled: true,
            paths: canary_paths.clone(),
            ban_ttl_secs,
        },
        ..Default::default()
    };
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));

    let canary = Arc::new(CanaryLayer::with_ban_table(
        canary_paths,
        Arc::clone(&ban_table),
        ban_ttl_secs,
    ));

    let mut scorer = Scorer::new(store, swap);
    scorer.set_canary(canary);

    (scorer, ban_table)
}

#[tokio::test]
async fn canary_path_triggers_block_and_score_100() {
    let (scorer, ban_table) = make_scorer_with_canary(vec!["/admin-test".to_string()], 3600);

    let ctx = make_ctx("/admin-test");
    let now_ms = 1_000_000;

    let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();

    assert_eq!(result.score, 100);
    assert!(matches!(result.action, WafAction::Block { .. }));

    // Verify IP was added to ban table
    let ip = ctx.client_ip;
    assert!(ban_table.contains(ip, now_ms));
}

#[tokio::test]
async fn non_canary_path_allows_normally() {
    let (scorer, ban_table) = make_scorer_with_canary(vec!["/admin-test".to_string()], 3600);

    let ctx = make_ctx("/normal-path");
    let now_ms = 1_000_000;

    let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();

    assert_eq!(result.score, 0);
    assert!(matches!(result.action, WafAction::Allow));

    // IP should not be banned
    assert!(!ban_table.contains(ctx.client_ip, now_ms));
}

#[tokio::test]
async fn canary_pin_survives_decay_window() {
    let (scorer, _ban_table) = make_scorer_with_canary(vec!["/trap".to_string()], 3600);

    let ctx = make_ctx("/trap");
    let now_ms = 1_000_000;

    // Trigger canary
    let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();
    assert_eq!(result.score, 100);

    // Advance time by 2x half-life (normal decay would reduce score)
    // But pin should keep score at 100
    let later_ms = now_ms + 600_000; // 10 minutes later
    let normal_ctx = make_ctx("/normal");

    // Read the state — should still be 100 due to pin
    let state = scorer.read(&ctx, None).await.unwrap();
    assert_eq!(state, Some(100));

    // Make a normal request from same IP
    let result2 = scorer.score(&normal_ctx, None, &[], None, later_ms).await.unwrap();
    // Score should still be 100 because of pin
    assert_eq!(result2.score, 100);
}

#[tokio::test]
async fn canary_pin_expires_after_ttl() {
    let ban_ttl_secs = 60; // 1 minute TTL for faster test
    let (scorer, ban_table) = make_scorer_with_canary(vec!["/honeypot".to_string()], ban_ttl_secs);

    let ctx = make_ctx("/honeypot");
    let now_ms = 1_000_000;

    // Trigger canary
    let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();
    assert_eq!(result.score, 100);
    assert!(ban_table.contains(ctx.client_ip, now_ms));

    // Advance time past TTL
    let expired_ms = now_ms + (i64::from(ban_ttl_secs) * 1000) + 1;

    // Ban table entry should be expired
    assert!(!ban_table.contains(ctx.client_ip, expired_ms));
}

#[tokio::test]
async fn canary_hot_reload_adds_new_path() {
    let (scorer, ban_table) = make_scorer_with_canary(vec!["/admin-test".to_string()], 3600);

    let now_ms = 1_000_000;

    // New path should not trigger initially
    let ctx_new = make_ctx("/api-debug2");
    let result1 = scorer.score(&ctx_new, None, &[], None, now_ms).await.unwrap();
    assert!(matches!(result1.action, WafAction::Allow));

    // Hot-reload to add new path
    // Note: In production this would be done via config reload
    // Here we directly reload the canary layer
    if let Some(ref canary) = scorer.canary {
        canary.reload(vec!["/admin-test".to_string(), "/api-debug2".to_string()]);
    }

    // Now the new path should trigger
    let result2 = scorer.score(&ctx_new, None, &[], None, now_ms + 1000).await.unwrap();
    assert_eq!(result2.score, 100);
    assert!(matches!(result2.action, WafAction::Block { .. }));
    assert!(ban_table.contains(ctx_new.client_ip, now_ms + 1000));
}

#[tokio::test]
async fn canary_disabled_does_not_trigger() {
    let store = Arc::new(MemoryRiskStore::new());

    let cfg = RiskConfig {
        enabled: true,
        canary: CanaryConfig {
            enabled: false, // Disabled
            paths: vec!["/admin-test".to_string()],
            ban_ttl_secs: 3600,
        },
        ..Default::default()
    };
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));

    let canary = Arc::new(CanaryLayer::with_paths(vec!["/admin-test".to_string()]));
    let mut scorer = Scorer::new(store, swap);
    scorer.set_canary(canary);

    let ctx = make_ctx("/admin-test");
    let result = scorer.score(&ctx, None, &[], None, 1_000_000).await.unwrap();

    // Should allow because canary is disabled in config
    assert!(matches!(result.action, WafAction::Allow));
}

#[tokio::test]
async fn partial_path_match_does_not_trigger() {
    let (scorer, ban_table) = make_scorer_with_canary(vec!["/admin-test".to_string()], 3600);

    let now_ms = 1_000_000;

    // Partial matches should NOT trigger
    let paths = ["/admin-test/", "/admin-test/foo", "/admin-testing", "admin-test"];

    for path in paths {
        let ctx = make_ctx(path);
        let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();
        assert!(
            matches!(result.action, WafAction::Allow),
            "Path '{path}' should not trigger canary"
        );
        assert!(!ban_table.contains(ctx.client_ip, now_ms));
    }
}

#[tokio::test]
async fn whitelist_bypasses_canary() {
    // Test that seed whitelist short-circuits BEFORE canary check
    // A whitelisted IP hitting a canary path should be allowed, not blocked

    let store = Arc::new(MemoryRiskStore::new());
    let ban_table = Arc::new(DynamicBanTable::new());

    // Create config with canary enabled
    let cfg = RiskConfig {
        enabled: true,
        canary: CanaryConfig {
            enabled: true,
            paths: vec!["/admin-test".to_string()],
            ban_ttl_secs: 3600,
        },
        ..Default::default()
    };
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));

    // Build seed layer with whitelist containing our test IP
    let test_ip: IpAddr = "192.168.1.100".parse().unwrap();
    let mut builder = SeedTablesBuilder::new();
    builder.add_whitelist(IpNetwork::new(test_ip, 32).unwrap());
    let tables = Arc::new(ArcSwapSeed::from(Arc::new(builder.build())));
    let seed = Arc::new(SeedLayer::new(tables, SeedDeltas::default()));

    // Build canary layer
    let canary = Arc::new(CanaryLayer::with_ban_table(
        vec!["/admin-test".to_string()],
        Arc::clone(&ban_table),
        3600,
    ));

    let mut scorer = Scorer::new(store, swap);
    scorer.set_seed(seed);
    scorer.set_canary(canary);

    // Request from whitelisted IP to canary path
    let ctx = make_ctx("/admin-test");
    let now_ms = 1_000_000;

    let result = scorer.score(&ctx, None, &[], None, now_ms).await.unwrap();

    // Should be ALLOWED because whitelist short-circuits before canary check
    assert!(
        matches!(result.action, WafAction::Allow),
        "Whitelisted IP should bypass canary and be allowed"
    );
    assert_eq!(result.score, 0);

    // IP should NOT be in ban table
    assert!(!ban_table.contains(ctx.client_ip, now_ms));
}
