//! FR-025 Phase 7: Redis store conformance tests.
//!
//! Runs the shared conformance suite against `RedisRiskStore`. Only executes
//! when `REDIS_TEST_URL` is set (e.g. `redis://127.0.0.1:6379`).

#![cfg(feature = "redis-store")]

use std::time::Duration;

use crate::risk::store::conformance::run_all;
use crate::risk::store::redis::{RedisRiskConfig, RedisRiskStore};

fn unique_prefix() -> String {
    format!(
        "waf_risk_conformance_{}:",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    )
}

/// Full conformance suite against real Redis.
#[tokio::test]
async fn redis_store_passes_conformance() {
    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        tracing::info!("skipping: REDIS_TEST_URL unset");
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ttl_secs: 3600,
        op_timeout: Duration::from_millis(500),
        breaker_threshold: 5,
        cache_capacity: 1000,
    })
    .await
    .expect("connect to REDIS_TEST_URL");

    run_all(&store).await;
}

/// Test that multiple applies accumulate correctly.
#[tokio::test]
async fn redis_apply_accumulates_score() {
    use crate::risk::key::RiskKey;
    use crate::risk::state::{Contributor, ContributorKind, SeedKind};
    use crate::risk::store::RiskStore;
    use std::net::{IpAddr, Ipv4Addr};

    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ttl_secs: 3600,
        op_timeout: Duration::from_millis(500),
        breaker_threshold: 5,
        cache_capacity: 1000,
    })
    .await
    .expect("connect");

    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
    let make_delta = |d: i16, ts: i64| Contributor::new(ContributorKind::Seed(SeedKind::Generic), d, ts);

    // First apply
    let r1 = store.apply(&key, &[make_delta(20, 1000)], 1000).await.unwrap();
    assert!(r1.is_new, "first apply should be new");
    assert_eq!(r1.state.clamped_score, 20);

    // Second apply
    let r2 = store.apply(&key, &[make_delta(15, 2000)], 2000).await.unwrap();
    assert!(!r2.is_new, "second apply should not be new");
    assert_eq!(r2.state.clamped_score, 35);

    // Third apply
    let r3 = store.apply(&key, &[make_delta(10, 3000)], 3000).await.unwrap();
    assert_eq!(r3.state.clamped_score, 45);
}

/// Test triple-key index convergence.
#[tokio::test]
async fn redis_triple_key_converges() {
    use crate::risk::key::{RiskKey, SessionId};
    use crate::risk::state::{Contributor, ContributorKind, SeedKind};
    use crate::risk::store::RiskStore;
    use std::net::{IpAddr, Ipv4Addr};

    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ttl_secs: 3600,
        op_timeout: Duration::from_millis(500),
        breaker_threshold: 5,
        cache_capacity: 1000,
    })
    .await
    .expect("connect");

    store.reset_all().await.unwrap();

    let make_delta = |d: i16| Contributor::new(ContributorKind::Seed(SeedKind::Generic), d, 1000);

    // Apply with all three axes
    let full_key = RiskKey {
        ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99))),
        fp_hash: Some(123_456_789),
        session: Some(SessionId::new(vec![0xAA, 0xBB, 0xCC, 0xDD])),
    };
    store.apply(&full_key, &[make_delta(50)], 1000).await.unwrap();

    // Read via IP only — should find state
    let ip_key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)));
    let state = store.read(&ip_key).await.unwrap();
    assert!(state.is_some());
    assert_eq!(state.unwrap().clamped_score, 50);

    // Read via fp_hash only
    let fp_key = RiskKey {
        ip: None,
        fp_hash: Some(123_456_789),
        session: None,
    };
    let state = store.read(&fp_key).await.unwrap();
    assert!(state.is_some());
    assert_eq!(state.unwrap().clamped_score, 50);

    // Read via session only
    let sess_key = RiskKey {
        ip: None,
        fp_hash: None,
        session: Some(SessionId::new(vec![0xAA, 0xBB, 0xCC, 0xDD])),
    };
    let state = store.read(&sess_key).await.unwrap();
    assert!(state.is_some());
    assert_eq!(state.unwrap().clamped_score, 50);
}

/// Test `force_max` sets score to 100 with pin.
#[tokio::test]
async fn redis_force_max_pins_score() {
    use crate::risk::key::RiskKey;
    use crate::risk::state::{Contributor, ContributorKind, SeedKind};
    use crate::risk::store::RiskStore;
    use std::net::{IpAddr, Ipv4Addr};

    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ttl_secs: 3600,
        op_timeout: Duration::from_millis(500),
        breaker_threshold: 5,
        cache_capacity: 1000,
    })
    .await
    .expect("connect");

    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 50, 50, 50)));
    let make_delta = |d: i16| Contributor::new(ContributorKind::Seed(SeedKind::Generic), d, 1000);

    // Initial apply with low score
    store.apply(&key, &[make_delta(25)], 1000).await.unwrap();

    // Force max
    store.force_max(&key, 10_000, 2000).await.unwrap();

    // Read should show max score with pin
    let state = store.read(&key).await.unwrap().unwrap();
    assert_eq!(state.clamped_score, 100);
    assert_eq!(state.pinned_until_ms, Some(10_000));
}

/// Test `reset_all` clears all keys.
#[tokio::test]
async fn redis_reset_all_clears_store() {
    use crate::risk::key::RiskKey;
    use crate::risk::state::{Contributor, ContributorKind, SeedKind};
    use crate::risk::store::RiskStore;
    use std::net::{IpAddr, Ipv4Addr};

    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ttl_secs: 3600,
        op_timeout: Duration::from_millis(500),
        breaker_threshold: 5,
        cache_capacity: 1000,
    })
    .await
    .expect("connect");

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 60, 60, 60)));
    let delta = Contributor::new(ContributorKind::Seed(SeedKind::Generic), 30, 1000);

    store.apply(&key, &[delta], 1000).await.unwrap();
    assert!(!store.is_empty().await);

    store.reset_all().await.unwrap();

    assert!(store.is_empty().await);
    assert!(store.read(&key).await.unwrap().is_none());
}
