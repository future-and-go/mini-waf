//! FR-012 phase-04 integration — full `TxVelocity` pipeline test.
//!
//! Exercises: `TxStore` → Classifiers → `RiskAggregator` signal emission.
//! Uses `LoggingAggregator` to capture signals without external deps.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use waf_engine::checks::tx_velocity::config::{ClassifierConfigs, RoleRule, SequenceCfg, VelocityCfg};
use waf_engine::checks::tx_velocity::role_tagger::RoleTagger;
use waf_engine::checks::tx_velocity::session_key::{SessionIdent, SessionKey};
use waf_engine::checks::tx_velocity::{EndpointRole, TxStore, TxVelocityConfig, default_classifiers};
use waf_engine::device_fp::aggregator::LoggingAggregator;
use waf_engine::device_fp::signal::Signal;

fn session_key(tag: &str) -> SessionKey {
    SessionKey {
        host: "test.example.com".to_string(),
        ident: SessionIdent::Cookie(format!("sess_{tag}")),
    }
}

fn role_rules() -> Vec<RoleRule> {
    vec![
        RoleRule {
            role: EndpointRole::Login,
            path: r"^/api/auth/login$".to_string(),
        },
        RoleRule {
            role: EndpointRole::Otp,
            path: r"^/api/auth/otp".to_string(),
        },
        RoleRule {
            role: EndpointRole::Deposit,
            path: r"^/api/wallet/deposit".to_string(),
        },
        RoleRule {
            role: EndpointRole::Withdrawal,
            path: r"^/api/wallet/withdraw".to_string(),
        },
        RoleRule {
            role: EndpointRole::LimitChange,
            path: r"^/api/settings/limit".to_string(),
        },
    ]
}

fn pipeline_config(cooldown_ms: u64) -> TxVelocityConfig {
    TxVelocityConfig {
        enabled: true,
        signal_cooldown_ms: cooldown_ms,
        session_ttl_secs: 3600,
        session_cookie: "SESSIONID".to_string(),
        janitor_period_secs: 60,
        role_tagger: RoleTagger::compile(&role_rules()).expect("compile rules"),
        classifiers: ClassifierConfigs {
            sequence: Some(SequenceCfg { min_human_ms: 1500 }),
            withdrawal_velocity: Some(VelocityCfg {
                max_count: 2,
                window_ms: 60_000,
            }),
            limit_change_velocity: Some(VelocityCfg {
                max_count: 1,
                window_ms: 30_000,
            }),
        },
    }
}

async fn flush_aggregator() {
    tokio::time::sleep(Duration::from_millis(15)).await;
}

// ─── Full pipeline: request → role tag → record → classifier → signal ───

#[tokio::test]
async fn full_pipeline_login_otp_fast_sequence_emits_signal() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );
    let tagger = RoleTagger::compile(&role_rules()).expect("compile");

    let key = session_key("fast-sequence");

    // Simulate Login → OTP within 500ms (below 1500ms threshold)
    let login_role = tagger.classify("/api/auth/login");
    assert_eq!(login_role, EndpointRole::Login);
    store.record(&key, login_role, true);

    // Small delay simulating fast bot
    tokio::time::sleep(Duration::from_millis(100)).await;

    let otp_role = tagger.classify("/api/auth/otp/verify");
    assert_eq!(otp_role, EndpointRole::Otp);
    store.record(&key, otp_role, true);
    flush_aggregator().await;

    let signals = agg.snapshot();
    assert!(
        signals.iter().any(|s| s.signals.iter().any(|sig| {
            matches!(
                sig,
                Signal::TxSequenceTooFast {
                    from: EndpointRole::Login,
                    to: EndpointRole::Otp,
                    ..
                }
            )
        })),
        "expected TxSequenceTooFast signal, got: {signals:?}"
    );
}

#[tokio::test]
async fn full_pipeline_withdrawal_velocity_breach_emits_signal() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );
    let tagger = RoleTagger::compile(&role_rules()).expect("compile");

    let key = session_key("withdrawal-burst");
    let role = tagger.classify("/api/wallet/withdraw");

    // 3 withdrawals exceeds max_count=2
    for _ in 0..3 {
        store.record(&key, role, true);
    }
    flush_aggregator().await;

    let signals = agg.snapshot();
    assert!(
        signals.iter().any(|s| s
            .signals
            .iter()
            .any(|sig| { matches!(sig, Signal::WithdrawalVelocity { count: 3, .. }) })),
        "expected WithdrawalVelocity signal, got: {signals:?}"
    );
}

#[tokio::test]
async fn full_pipeline_limit_change_burst_emits_signal() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );
    let tagger = RoleTagger::compile(&role_rules()).expect("compile");

    let key = session_key("limit-burst");
    let role = tagger.classify("/api/settings/limit");

    // 2 limit changes exceeds max_count=1
    for _ in 0..2 {
        store.record(&key, role, true);
    }
    flush_aggregator().await;

    let signals = agg.snapshot();
    assert!(
        signals.iter().any(|s| s
            .signals
            .iter()
            .any(|sig| { matches!(sig, Signal::LimitChangeBurst { count: 2, .. }) })),
        "expected LimitChangeBurst signal, got: {signals:?}"
    );
}

// ─── Negative controls ─────────────────────────────────────────────────

#[tokio::test]
async fn pipeline_slow_sequence_does_not_fire() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );

    let key = session_key("slow-human");
    store.record(&key, EndpointRole::Login, true);

    // 2 second delay — above 1500ms threshold (human speed)
    tokio::time::sleep(Duration::from_secs(2)).await;

    store.record(&key, EndpointRole::Otp, true);
    flush_aggregator().await;

    let signals = agg.snapshot();
    assert!(
        !signals.iter().any(|s| s
            .signals
            .iter()
            .any(|sig| { matches!(sig, Signal::TxSequenceTooFast { .. }) })),
        "should not fire for slow sequence: {signals:?}"
    );
}

#[tokio::test]
async fn pipeline_below_velocity_threshold_silent() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );

    let key = session_key("normal-user");
    // Only 2 withdrawals — at threshold, not over
    for _ in 0..2 {
        store.record(&key, EndpointRole::Withdrawal, true);
    }
    flush_aggregator().await;

    let signals = agg.snapshot();
    assert!(
        !signals.iter().any(|s| s
            .signals
            .iter()
            .any(|sig| { matches!(sig, Signal::WithdrawalVelocity { .. }) })),
        "should be silent at threshold: {signals:?}"
    );
}

#[tokio::test]
async fn pipeline_disabled_config_emits_nothing() {
    let mut cfg_val = pipeline_config(0);
    cfg_val.enabled = false;
    let cfg = Arc::new(ArcSwap::from_pointee(cfg_val));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );

    let key = session_key("disabled");
    // Would breach threshold if enabled
    for _ in 0..5 {
        store.record(&key, EndpointRole::Withdrawal, true);
    }
    flush_aggregator().await;

    assert!(agg.snapshot().is_empty(), "disabled config should emit nothing");
}

// ─── Cooldown suppression ──────────────────────────────────────────────

#[tokio::test]
async fn pipeline_cooldown_suppresses_duplicate_signals() {
    // Long cooldown: 60s
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(60_000)));
    let agg = LoggingAggregator::new(16);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );

    let key = session_key("cooldown-test");

    // First breach — should fire
    for _ in 0..3 {
        store.record(&key, EndpointRole::Withdrawal, true);
    }
    flush_aggregator().await;

    // Second breach — cooldown should suppress
    for _ in 0..3 {
        store.record(&key, EndpointRole::Withdrawal, true);
    }
    flush_aggregator().await;

    let signals = agg.snapshot();
    assert_eq!(signals.len(), 1, "cooldown should suppress second signal: {signals:?}");
}

// ─── Hot-reload friendly ───────────────────────────────────────────────

#[tokio::test]
async fn hot_reload_threshold_change_takes_effect() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let agg = LoggingAggregator::new(8);
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    );

    let key = session_key("hot-reload");

    // 3 withdrawals fires with max_count=2
    for _ in 0..3 {
        store.record(&key, EndpointRole::Withdrawal, true);
    }
    flush_aggregator().await;
    assert!(!agg.snapshot().is_empty(), "should fire before reload");

    // Hot-reload: raise threshold to 10
    let mut new_cfg = pipeline_config(0);
    new_cfg.classifiers.withdrawal_velocity = Some(VelocityCfg {
        max_count: 10,
        window_ms: 60_000,
    });
    cfg.store(Arc::new(new_cfg));

    // Clear aggregator for fresh check
    let agg2 = LoggingAggregator::new(8);
    let store2 = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg2.clone()),
    );

    let key2 = session_key("after-reload");
    // Same 3 withdrawals — now below threshold
    for _ in 0..3 {
        store2.record(&key2, EndpointRole::Withdrawal, true);
    }
    flush_aggregator().await;

    assert!(agg2.snapshot().is_empty(), "should be silent after threshold raised");
}

// ─── Unmatched paths ignored ───────────────────────────────────────────

#[tokio::test]
async fn unmatched_paths_not_recorded() {
    let cfg = Arc::new(ArcSwap::from_pointee(pipeline_config(0)));
    let store = TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(LoggingAggregator::new(1)),
    );
    let tagger = RoleTagger::compile(&role_rules()).expect("compile");

    let key = session_key("unmatched");
    let role = tagger.classify("/api/unknown/endpoint");
    assert_eq!(role, EndpointRole::None);

    store.record(&key, role, true);

    assert!(
        store.snapshot(&key).is_none(),
        "EndpointRole::None should not create session entry"
    );
}
