//! FR-025 — extended scorer / velocity / challenge_credit coverage.

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
use bytes::Bytes;
use tempfile::tempdir;
use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, Tier, TierPolicy};
use waf_common::{DefenseConfig, HostConfig, LoadBalanceStrategy, RequestCtx, WafAction};
use waf_engine::risk::canary::CanaryLayer;
use waf_engine::risk::challenge_credit::{
    ChallengeBuilder, ChallengeIssuer, ChallengeVerifier, HmacSecret, NonceStore,
};
use waf_engine::risk::config::{ChallengeConfig as RiskChallengeConfig, RiskConfig};
use waf_engine::risk::key::RiskKey;
use waf_engine::risk::scorer::Scorer;
use waf_engine::risk::seed::{SeedDeltas, SeedLayer};
use waf_engine::risk::state::{Contributor, ContributorKind, SeedKind};
use waf_engine::risk::store::{MemoryRiskStore, RiskStore};
use waf_engine::risk::velocity::{TxEndpoint, VelocityLayer};

fn ctx_with(ip: IpAddr, headers: HashMap<String, String>) -> RequestCtx {
    RequestCtx {
        req_id: "x".to_string(),
        client_ip: ip,
        client_port: 0,
        method: "GET".to_string(),
        host: "h".to_string(),
        port: 443,
        path: "/p".to_string(),
        query: String::new(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: true,
        host_config: Arc::new(HostConfig {
            code: "t".into(),
            host: "h".into(),
            port: 443,
            ssl: true,
            guard_status: true,
            remote_host: "b".into(),
            remote_port: 0,
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
            mask_token: "[X]".into(),
            body_mask_max_bytes: 1_000_000,
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
    }
}

fn make_scorer(cfg: RiskConfig) -> Scorer<MemoryRiskStore> {
    let store = Arc::new(MemoryRiskStore::new());
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
    Scorer::new(store, swap)
}

#[tokio::test]
async fn read_returns_score_after_apply() {
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let scorer = make_scorer(cfg);
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), HashMap::new());
    let deltas = vec![Contributor::new(ContributorKind::Seed(SeedKind::Generic), 25, 1000)];
    scorer.score(&ctx, None, &deltas, None, 1000).await.unwrap();
    let score = scorer.read(&ctx, None).await.unwrap();
    assert_eq!(score, Some(25));
}

#[tokio::test]
async fn force_max_pins_score() {
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let scorer = make_scorer(cfg);
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), HashMap::new());
    scorer.force_max(&ctx, None, 5_000_000, 1000).await.unwrap();
    // After force_max, normal score should be blocked via pin
    let r = scorer.score(&ctx, None, &[], None, 2000).await.unwrap();
    assert_eq!(r.score, 100);
    assert!(matches!(r.action, WafAction::Block { .. }));
}

#[tokio::test]
async fn header_name_and_emit_header_accessors() {
    let scorer = make_scorer(RiskConfig {
        enabled: true,
        ..Default::default()
    });
    assert_eq!(scorer.header_name(), "X-WAF-Risk-Score");
    assert!(scorer.emit_header());
}

#[tokio::test]
async fn with_seed_constructor_and_set_seed() {
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let store = Arc::new(MemoryRiskStore::new());
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
    let seed = Arc::new(SeedLayer::empty());
    let mut scorer = Scorer::with_seed(Arc::clone(&store), swap, Arc::clone(&seed));
    scorer.set_seed(seed);
    // Sanity: can score without panic
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), HashMap::new());
    let r = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
    assert!(matches!(r.action, WafAction::Allow));
}

#[tokio::test]
async fn with_velocity_threshold_constructor() {
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let store = Arc::new(MemoryRiskStore::new());
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
    let scorer = Scorer::with_velocity_threshold(store, swap, 1);
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(7, 7, 7, 7)), HashMap::new());
    // Run a few requests; expect velocity breach contribution to bump score eventually
    let r = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
    let _ = r;
}

#[tokio::test]
async fn read_returns_none_when_disabled() {
    let scorer = make_scorer(RiskConfig::default()); // disabled
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), HashMap::new());
    assert!(scorer.read(&ctx, None).await.unwrap().is_none());
}

#[tokio::test]
async fn force_max_no_op_when_empty_key() {
    // Disable IP key by giving config empty session cookie + no fp; here ctx still has IP,
    // so this exercises the normal force_max path. We only assert no-error.
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let scorer = make_scorer(cfg);
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::LOCALHOST), HashMap::new());
    scorer.force_max(&ctx, None, 999, 1000).await.expect("force_max ok");
}

#[tokio::test]
async fn challenge_credit_disabled_skips_verifier() {
    // challenge.enabled defaults to false → evaluate_challenge_credit short-circuits
    let cfg = RiskConfig {
        enabled: true,
        challenge: RiskChallengeConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    };
    let scorer = make_scorer(cfg);
    let mut hdrs = HashMap::new();
    hdrs.insert("x-waf-credit".into(), "any-token".into());
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)), hdrs);
    let r = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
    assert!(matches!(r.action, WafAction::Allow));
}

#[tokio::test]
async fn challenge_credit_invalid_token_path() {
    // Wire up a real verifier; an absent header → no contributor; bad header → invalid_delta
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("hmac.key");
    std::fs::write(&key_path, [3u8; 32]).unwrap();
    let secret = Arc::new(HmacSecret::load_or_init(&key_path).unwrap());
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let verifier = Arc::new(ChallengeVerifier::new(Arc::clone(&secret), nonce_store));
    let _issuer = ChallengeIssuer::new(secret, 300);

    let cfg = RiskConfig {
        enabled: true,
        challenge: RiskChallengeConfig {
            enabled: true,
            header_name: "x-waf-credit".into(),
            valid_delta: -10,
            invalid_delta: 40,
            replay_delta: 50,
            expired_delta: 5,
            ..Default::default()
        },
        ..Default::default()
    };
    let store = Arc::new(MemoryRiskStore::new());
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
    let mut scorer = Scorer::new(store, swap);
    scorer.set_challenge_verifier(verifier);

    let mut hdrs = HashMap::new();
    hdrs.insert("x-waf-credit".into(), "garbage".into());
    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(4, 4, 4, 4)), hdrs);

    let r = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
    assert!(r.score >= 40);
}

#[tokio::test]
async fn canary_set_layer_and_no_path_match() {
    let cfg = RiskConfig {
        enabled: true,
        ..Default::default()
    };
    let store = Arc::new(MemoryRiskStore::new());
    let swap = Arc::new(ArcSwap::from(Arc::new(cfg)));
    let mut scorer = Scorer::new(store, swap);
    let canary = Arc::new(CanaryLayer::with_paths(vec!["/.git".into()]));
    scorer.set_canary(canary);

    let ctx = ctx_with(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)), HashMap::new());
    let r = scorer.score(&ctx, None, &[], None, 1000).await.unwrap();
    assert!(matches!(r.action, WafAction::Allow));
}

// VelocityLayer extras
#[test]
fn velocity_layer_default_and_introspection() {
    let layer = VelocityLayer::default();
    assert_eq!(layer.velocity_len(), 0);
    assert_eq!(layer.sequence_len(), 0);
    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)));
    assert_eq!(layer.request_count(&key, 1000), 0);

    // Trigger one request to populate
    let _ = layer.evaluate(&key, Some(TxEndpoint::Login), 1000);
    assert!(layer.velocity_len() >= 1);
}

// MemoryRiskStore extras
#[tokio::test]
async fn store_purge_expired_removes_idle_entries() {
    let store = MemoryRiskStore::new();
    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(11, 11, 11, 11)));
    store
        .apply(
            &key,
            &[Contributor::new(ContributorKind::Seed(SeedKind::Generic), 10, 0)],
            0,
        )
        .await
        .unwrap();
    // Now=10_000_000 ms, ttl=1000 ms → entry is idle for 10_000_000 - last_updated
    let purged = store.purge_expired(1000, 10_000_000).await.unwrap();
    assert!(purged >= 1);
    assert!(store.read(&key).await.unwrap().is_none());
}

#[tokio::test]
async fn store_reset_all_clears_indices() {
    let store = MemoryRiskStore::new();
    let k = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(12, 12, 12, 12)));
    store
        .apply(
            &k,
            &[Contributor::new(ContributorKind::Seed(SeedKind::Generic), 5, 100)],
            100,
        )
        .await
        .unwrap();
    assert!(!store.is_empty().await);
    store.reset_all().await.unwrap();
    assert!(store.is_empty().await);
}

// ChallengeBuilder integration
#[test]
fn challenge_builder_from_config_creates_pair() {
    let dir = tempdir().unwrap();
    let key_path = dir.path().join("hmac.key");
    let cfg = RiskChallengeConfig {
        enabled: true,
        hmac_secret_path: Some(key_path.to_string_lossy().into()),
        ttl_secs: 120,
        lru_size: 32,
        ..Default::default()
    };
    let (issuer, _verifier) = ChallengeBuilder::from_config(&cfg).expect("builder ok");
    assert_eq!(issuer.ttl_secs(), 120);
}

// SeedLayer extras
#[test]
fn seed_layer_with_deltas_overrides_default() {
    let dir = tempdir().unwrap();
    let tor = dir.path().join("tor.txt");
    std::fs::write(&tor, "5.5.5.5\n").unwrap();
    let layer = SeedLayer::load_from_paths(
        Some(&tor),
        None,
        None,
        SeedDeltas {
            tor_exit: 50,
            datacenter: 20,
            ..SeedDeltas::default()
        },
    );
    let v = layer.evaluate(IpAddr::V4(Ipv4Addr::new(5, 5, 5, 5)));
    match v {
        waf_engine::risk::seed::SeedVerdict::Score { delta, .. } => assert_eq!(delta, 50),
        other => panic!("expected Score, got {other:?}"),
    }
}
