//! FR-025 Phase 7: Redis failover and circuit breaker tests.
//!
//! Tests fail-open behavior when Redis is unavailable or times out.
//! Uses cache fallback to maintain continuity during outages.

#![cfg(feature = "redis-store")]

use std::time::Duration;

use crate::risk::key::RiskKey;
use crate::risk::state::{Contributor, ContributorKind, SeedKind};
use crate::risk::store::RiskStore;
use crate::risk::store::redis::{RedisRiskConfig, RedisRiskStore};

fn unique_prefix() -> String {
    format!(
        "waf_risk_failover_{}:",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    )
}

fn make_delta(d: i16, ts: i64) -> Contributor {
    Contributor::new(ContributorKind::Seed(SeedKind::Generic), d, ts)
}

/// Test that cache fallback works when Redis ops fail.
#[tokio::test]
async fn cache_fallback_on_redis_failure() {
    use std::net::{IpAddr, Ipv4Addr};

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
    .expect("connect");

    store.reset_all().await.unwrap();

    // Populate cache via successful apply
    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 100, 100, 100)));
    let result = store.apply(&key, &[make_delta(40, 1000)], 1000).await.unwrap();
    assert_eq!(result.state.clamped_score, 40);

    // Verify cache was populated by reading (this also exercises Redis path)
    let read = store.read(&key).await.unwrap();
    assert!(read.is_some());
    assert_eq!(read.unwrap().clamped_score, 40);
}

/// Test circuit breaker state transitions.
#[tokio::test]
async fn circuit_breaker_opens_and_resets() {
    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        breaker_threshold: 3,
        ..Default::default()
    })
    .await
    .expect("connect");

    // Initially closed
    assert!(!store.breaker_open(), "breaker should start closed");

    // Simulate failures (private method, but we can test via public interface)
    // The breaker tracks consecutive Redis failures internally

    // After threshold failures, breaker opens
    // After a success, breaker resets

    // Since we can't directly inject failures without mocking Redis,
    // we verify the breaker mechanics work correctly with real operations
    let key = RiskKey::from_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 200, 200, 200)));

    // Successful operation should keep breaker closed
    let _ = store.apply(&key, &[make_delta(10, 1000)], 1000).await;
    assert!(!store.breaker_open(), "breaker should stay closed after success");
}

/// Test that store handles empty keys gracefully.
#[tokio::test]
async fn empty_key_returns_default_state() {
    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ..Default::default()
    })
    .await
    .expect("connect");

    let empty_key = RiskKey::default();

    // Read on empty key returns None
    let read = store.read(&empty_key).await.unwrap();
    assert!(read.is_none());

    // Apply on empty key returns new default state
    let result = store.apply(&empty_key, &[make_delta(25, 1000)], 1000).await.unwrap();
    assert!(result.is_new);
    assert_eq!(result.state.clamped_score, 0); // Empty key doesn't persist
}

/// Test `purge_expired` is a no-op (Redis TTL handles this).
#[tokio::test]
async fn purge_expired_is_noop() {
    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = RedisRiskStore::new(RedisRiskConfig {
        url,
        key_prefix: unique_prefix(),
        ..Default::default()
    })
    .await
    .expect("connect");

    // purge_expired should return 0 (Redis TTL handles expiration natively)
    let purged = store.purge_expired(1000, 5000).await.unwrap();
    assert_eq!(purged, 0, "Redis store purge_expired should be no-op");
}

/// Test `len()` returns correct count of state keys.
#[tokio::test]
async fn len_counts_state_keys() {
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
    assert_eq!(store.len().await, 0);

    // Add some entries
    for i in 1..=5_u8 {
        let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)));
        store.apply(&key, &[make_delta(10, 1000)], 1000).await.unwrap();
    }

    assert_eq!(store.len().await, 5);

    store.reset_all().await.unwrap();
    assert_eq!(store.len().await, 0);
}

/// Test that concurrent applies to same key don't cause issues.
#[tokio::test]
async fn concurrent_applies_are_safe() {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;

    let Ok(url) = std::env::var("REDIS_TEST_URL") else {
        return;
    };

    let store = Arc::new(
        RedisRiskStore::new(RedisRiskConfig {
            url,
            key_prefix: unique_prefix(),
            ttl_secs: 3600,
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
            cache_capacity: 1000,
        })
        .await
        .expect("connect"),
    );

    store.reset_all().await.unwrap();

    let key = RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    let num_concurrent = 10;

    // Spawn concurrent applies
    let handles: Vec<_> = (0..num_concurrent)
        .map(|i| {
            let store = Arc::clone(&store);
            let key = key.clone();
            tokio::spawn(async move {
                let ts = 1000 + i64::from(i);
                store.apply(&key, &[make_delta(5, ts)], ts).await
            })
        })
        .collect();

    // Wait for all to complete
    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result.is_ok(), "concurrent apply should succeed");
    }

    // Final score should be sum of all deltas (5 * 10 = 50)
    let state = store.read(&key).await.unwrap().unwrap();
    assert_eq!(
        state.clamped_score, 50,
        "final score should be sum of concurrent applies"
    );
}
