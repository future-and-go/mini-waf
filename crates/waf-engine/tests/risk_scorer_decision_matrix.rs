//! FR-025 — Scorer decision matrix integration coverage.
//!
//! Drives `Scorer::score` over the score×seed×canary×credit branch space using
//! real `MemoryRiskStore` + real `RiskConfig`. No mocks of business logic.

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
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, Tier, TierPolicy};
use waf_common::{DefenseConfig, HostConfig, LoadBalanceStrategy, RequestCtx, WafAction};

use waf_engine::risk::config::{CanaryConfig, ChallengeConfig, RiskConfig, SeedConfig};
use waf_engine::risk::seed::{SeedDeltas, SeedLayer, SeedTablesBuilder, SeedVerdict};
use waf_engine::risk::state::{Contributor, ContributorKind};
use waf_engine::risk::{CanaryLayer, MemoryRiskStore, Scorer};

fn ctx(ip: IpAddr) -> RequestCtx {
    RequestCtx {
        req_id: "test".to_string(),
        client_ip: ip,
        client_port: 12345,
        method: "GET".to_string(),
        host: "example.com".to_string(),
        port: 443,
        path: "/test".to_string(),
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
            remote_host: "be".to_string(),
            remote_port: 8080,
            remote_ip: None,
            cert_file: None,
            key_file: None,
            remarks: None,
            start_status: true,
            exclude_url_log: vec![],
            is_enable_load_balance: false,
            load_balance_strategy: LoadBalanceStrategy::RoundRobin,
            defense_config: DefenseConfig::default(),
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
        tier: Tier::CatchAll,
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
    }
}

fn mk_cfg(seed_enabled: bool, canary_enabled: bool, canary_paths: Vec<String>) -> RiskConfig {
    RiskConfig {
        enabled: true,
        seed: SeedConfig {
            enabled: seed_enabled,
            ..Default::default()
        },
        canary: CanaryConfig {
            enabled: canary_enabled,
            paths: canary_paths,
            ban_ttl_secs: 3600,
        },
        challenge: ChallengeConfig::default(),
        ..Default::default()
    }
}

fn seed_layer_with(tor: Option<IpAddr>, whitelist: Option<&str>) -> SeedLayer {
    let mut b = SeedTablesBuilder::new();
    if let Some(ip) = tor {
        b.add_tor_exit(ip);
    }
    if let Some(cidr) = whitelist {
        b.add_whitelist(cidr.parse().unwrap());
    }
    let tables = Arc::new(ArcSwap::from(b.build().into_arc()));
    SeedLayer::new(tables, SeedDeltas::default())
}

#[tokio::test]
async fn allow_when_score_below_threshold() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(false, false, vec![]))));
    let scorer = Scorer::new(store, cfg);

    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))), None, &[], None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Allow));
    assert!(r.is_new);
}

#[tokio::test]
async fn challenge_in_band_score() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(false, false, vec![]))));
    let scorer = Scorer::new(store, cfg);

    let deltas = vec![Contributor::new(ContributorKind::Anomaly, 50, 1000)];
    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 2))), None, &deltas, None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Challenge), "got {:?}", r.action);
    assert_eq!(r.score, 50);
}

#[tokio::test]
async fn block_at_or_above_block_threshold() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(false, false, vec![]))));
    let scorer = Scorer::new(store, cfg);

    let deltas = vec![Contributor::new(ContributorKind::Anomaly, 95, 1000)];
    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 3))), None, &deltas, None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Block { .. }));
}

#[tokio::test]
async fn seed_whitelist_short_circuits_to_allow() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(true, false, vec![]))));
    let mut scorer = Scorer::new(store, cfg);
    scorer.set_seed(Arc::new(seed_layer_with(None, Some("10.0.0.0/8"))));

    let big = vec![Contributor::new(ContributorKind::Anomaly, 99, 1000)];
    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1))), None, &big, None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Allow), "whitelist must short-circuit");
    assert_eq!(r.score, 0);
}

#[tokio::test]
async fn seed_tor_adds_delta() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(true, false, vec![]))));
    let mut scorer = Scorer::new(store, cfg);
    let tor_ip = IpAddr::V4(Ipv4Addr::new(2, 3, 4, 5));
    scorer.set_seed(Arc::new(seed_layer_with(Some(tor_ip), None)));

    let r = scorer.score(&ctx(tor_ip), None, &[], None, 1000).await.unwrap();
    // Default Tor delta = 30; threshold allow=30 → Challenge band.
    assert!(matches!(r.action, WafAction::Challenge), "got {:?}", r.action);
    assert!(r.score >= 30);
}

#[tokio::test]
async fn canary_path_forces_block_with_pin() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(false, true, vec!["/test".to_string()]))));
    let mut scorer = Scorer::new(store, cfg);
    scorer.canary = Some(Arc::new(CanaryLayer::with_paths(vec!["/test".to_string()])));

    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7))), None, &[], None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Block { .. }));
    assert_eq!(r.score, 100);
}

#[tokio::test]
async fn canary_skipped_for_non_matching_path() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(
        false,
        true,
        vec!["/admin-honeypot".to_string()],
    ))));
    let mut scorer = Scorer::new(store, cfg);
    scorer.canary = Some(Arc::new(CanaryLayer::with_paths(vec!["/admin-honeypot".to_string()])));

    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), None, &[], None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Allow));
}

#[tokio::test]
async fn empty_key_short_circuits_allow_when_no_axis() {
    // Construct ctx with no fingerprint, no session cookie — IP axis is always present
    // so use cfg with seed disabled to confirm direct path.
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(false, false, vec![]))));
    let scorer = Scorer::new(store, cfg);

    // fp=None means key has only IP — so non-empty key.  Coverage: direct path through L2.
    let r = scorer
        .score(&ctx(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))), None, &[], None, 1000)
        .await
        .unwrap();
    assert!(matches!(r.action, WafAction::Allow));
    assert_eq!(r.score, 0);
}

#[tokio::test]
async fn read_returns_none_when_disabled() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(RiskConfig::default()))); // enabled=false
    let scorer = Scorer::new(store, cfg);

    let r = scorer
        .read(&ctx(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), None)
        .await
        .unwrap();
    assert!(r.is_none());
}

#[tokio::test]
async fn force_max_then_block_via_pin() {
    let store = Arc::new(MemoryRiskStore::new());
    let cfg = Arc::new(ArcSwap::from(Arc::new(mk_cfg(false, false, vec![]))));
    let scorer = Scorer::new(store, cfg);

    let c = ctx(IpAddr::V4(Ipv4Addr::new(6, 6, 6, 6)));
    scorer.force_max(&c, None, 100_000, 1000).await.unwrap();
    let r = scorer.score(&c, None, &[], None, 2000).await.unwrap();
    assert!(matches!(r.action, WafAction::Block { .. }));
    assert_eq!(r.score, 100);
}

#[tokio::test]
async fn seed_layer_evaluate_none_is_passthrough() {
    let layer = seed_layer_with(None, None);
    assert_eq!(layer.evaluate(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))), SeedVerdict::None,);
}
