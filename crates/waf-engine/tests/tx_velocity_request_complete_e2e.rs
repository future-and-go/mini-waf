//! End-to-end FR-012: request → record → on_request_complete → set_outcome → signal.
//!
//! Exercises the engine API surface (`check` + `on_request_complete`) without
//! standing up a real Pingora proxy. Locks in the contract that classifiers
//! see honest `ok_count` values and that origin-down / WAF-blocked requests
//! leave events as Pending.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::doc_markdown,
    unused_imports
)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use waf_common::RequestCtx;
use waf_engine::checks::Check;
use waf_engine::checks::tx_velocity::{
    TxStore, TxVelocityCheck, TxVelocityConfig, TxVelocityFileConfig, default_classifiers,
};
use waf_engine::device_fp::aggregator::LoggingAggregator;
use waf_engine::device_fp::signal::Signal;

fn config_yaml() -> Arc<ArcSwap<TxVelocityConfig>> {
    let yaml = r#"
tx_velocity:
  enabled: true
  session_cookie: SID
  signal_cooldown_ms: 0
  endpoint_roles:
    - role: withdrawal
      path: "^/api/withdraw"
  classifiers:
    withdrawal_velocity:
      max_count: 2
      window_ms: 60000
"#;
    Arc::new(ArcSwap::from(
        TxVelocityFileConfig::from_yaml_str(yaml).expect("parse cfg"),
    ))
}

fn build_request_ctx(path: &str, cookie_name: &str, cookie_val: &str) -> RequestCtx {
    let mut cookies = HashMap::new();
    if !cookie_val.is_empty() {
        cookies.insert(cookie_name.to_string(), cookie_val.to_string());
    }
    RequestCtx {
        req_id: "r".to_string(),
        client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        method: "POST".to_string(),
        host: "bank.example.com".to_string(),
        port: 443,
        path: path.to_string(),
        is_tls: true,
        cookies,
        ..Default::default()
    }
}

async fn flush() {
    tokio::time::sleep(Duration::from_millis(15)).await;
}

#[tokio::test]
async fn three_2xx_withdrawals_emit_full_ok_count() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u1");
    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 200, true);
    }
    flush().await;

    let snap = agg.snapshot();
    assert!(
        snap.iter().any(|s| matches!(
            s.signals.first(),
            Some(Signal::WithdrawalVelocity {
                count: 3,
                ok_count: 3,
                ..
            })
        )),
        "expected count=3 ok_count=3, got {snap:?}",
    );
}

#[tokio::test]
async fn three_4xx_withdrawals_emit_zero_ok_count() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u2");
    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 403, true);
    }
    flush().await;

    let snap = agg.snapshot();
    assert!(
        snap.iter().any(|s| matches!(
            s.signals.first(),
            Some(Signal::WithdrawalVelocity {
                count: 3,
                ok_count: 0,
                ..
            })
        )),
        "expected ok_count=0 for denied burst, got {snap:?}",
    );
}

#[tokio::test]
async fn fingerprint_fallback_when_no_cookie() {
    use waf_common::{FingerprintValue, FpKey};

    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let fp = Arc::new(FpKey {
        ja3: Some(FingerprintValue::new("ja3-x")),
        ..FpKey::default()
    });
    let mut ctx = build_request_ctx("/api/withdraw", "SID", "");
    ctx.cookies.clear();
    ctx.device_fp = Some(Arc::clone(&fp));

    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 200, true);
    }
    flush().await;

    let snap = agg.snapshot();
    assert!(
        snap.iter().any(|s| s.key == *fp),
        "fp identity must appear in aggregator submission key: {snap:?}",
    );
}

#[tokio::test]
async fn origin_down_502_does_not_mark_failed() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u-orig-down");
    for _ in 0..3 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 502, false);
    }
    flush().await;

    assert!(
        agg.snapshot().is_empty(),
        "origin-down must NOT register as user denial: {:?}",
        agg.snapshot()
    );
}

#[tokio::test]
async fn waf_blocked_then_legit_2xx_emits_clean_count() {
    let cfg = config_yaml();
    let agg = LoggingAggregator::new(8);
    let store = Arc::new(TxStore::with_pipeline(
        Arc::clone(&cfg),
        default_classifiers(&cfg.load()),
        Arc::new(agg.clone()),
    ));
    let check = TxVelocityCheck::new(cfg, Arc::clone(&store));

    let mut ctx = build_request_ctx("/api/withdraw", "SID", "u-victim");
    // 16 WAF-blocked attempts pre-burn the ring as Pending events.
    for _ in 0..16 {
        check.check(&mut ctx);
        check.on_request_complete(&ctx, 403, false);
    }
    // Now one legit 2xx (count=1) arrives.
    check.check(&mut ctx);
    check.on_request_complete(&ctx, 200, true);
    flush().await;

    // Threshold is max_count=2; count of settled events is 1 → no signal.
    let snap = agg.snapshot();
    assert!(
        snap.is_empty(),
        "victim's first legit withdrawal must NOT see a poisoned ring: {snap:?}"
    );
}
