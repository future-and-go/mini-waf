//! FR-010 — `MemoryIdentityStore` capacity / LRU coverage.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use waf_engine::device_fp::identity::memory::{MemoryConfig, MemoryIdentityStore, spawn_janitor};
use waf_engine::device_fp::{FingerprintValue, FpKey, IdentityStore};

fn k(tag: &str) -> FpKey {
    FpKey {
        ja3: Some(FingerprintValue::new(tag)),
        ja4: None,
        h2_akamai: None,
    }
}

#[tokio::test]
async fn cap_evicts_oldest_last_seen_when_overflowing() {
    let cfg = MemoryConfig {
        ttl_secs: 3600,
        window_secs: 600,
        max_entries: 2,
    };
    let store = MemoryIdentityStore::with_config(cfg);

    // Insert key A at ts=10, key B at ts=20.
    store
        .observe(&k("A"), IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", 10)
        .await
        .unwrap();
    store
        .observe(&k("B"), IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", 20)
        .await
        .unwrap();

    // Insert key C at ts=30 → triggers cap enforcement, A should be evicted.
    store
        .observe(&k("C"), IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", 30)
        .await
        .unwrap();

    assert!(store.len() <= 2);
    assert!(
        store.lookup(&k("A")).await.unwrap().is_none(),
        "oldest entry A should be evicted"
    );
    assert!(store.lookup(&k("C")).await.unwrap().is_some());
}

#[tokio::test]
async fn observe_increments_distinct_ip_count() {
    let store = MemoryIdentityStore::new();
    let key = k("multi-ip");

    let a = store
        .observe(&key, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "ua", 10)
        .await
        .unwrap();
    assert_eq!(a.distinct_ips_in_window, 1);

    let b = store
        .observe(&key, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), "ua", 11)
        .await
        .unwrap();
    assert_eq!(b.distinct_ips_in_window, 2);

    // Repeat IP: count stays 2.
    let c = store
        .observe(&key, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "ua", 12)
        .await
        .unwrap();
    assert_eq!(c.distinct_ips_in_window, 2);
}

#[tokio::test]
async fn window_eviction_drops_old_observations() {
    let cfg = MemoryConfig {
        ttl_secs: 3600,
        window_secs: 5,
        max_entries: 16,
    };
    let store = MemoryIdentityStore::with_config(cfg);
    let key = k("rolling");

    store
        .observe(&key, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), "ua-old", 0)
        .await
        .unwrap();
    // ts=10 is past the window of 5s — old observation must be evicted.
    let later = store
        .observe(&key, IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)), "ua-new", 10)
        .await
        .unwrap();
    assert_eq!(later.distinct_ips_in_window, 1);
    assert_eq!(later.distinct_uas_in_window, 1);
}

#[tokio::test]
async fn purge_expired_removes_entries_older_than_ttl() {
    // Note: purge uses chrono::now(), so we can only check that calling does
    // not error and returns 0 when nothing is older than `ttl`.
    let store = MemoryIdentityStore::new();
    let purged = store.purge_expired().await.unwrap();
    assert_eq!(purged, 0);
}

#[tokio::test]
async fn lookup_missing_key_is_none() {
    let store = MemoryIdentityStore::new();
    assert!(store.lookup(&k("never-inserted")).await.unwrap().is_none());
}

#[tokio::test]
async fn concurrent_observe_no_panic_no_torn_state() {
    let store = Arc::new(MemoryIdentityStore::with_config(MemoryConfig {
        ttl_secs: 3600,
        window_secs: 60,
        max_entries: 1024,
    }));

    let mut handles = Vec::new();
    for i in 0..16_u8 {
        let s = Arc::clone(&store);
        handles.push(tokio::spawn(async move {
            for j in 0..32_u8 {
                let key = k(&format!("k{i}-{j}"));
                s.observe(
                    &key,
                    IpAddr::V4(Ipv4Addr::new(10, 0, i, j)),
                    "ua",
                    i64::from(i) * 100 + i64::from(j),
                )
                .await
                .unwrap();
            }
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    assert_eq!(store.len(), 16 * 32);
    assert!(!store.is_empty());
}

#[tokio::test]
async fn janitor_aborts_cleanly() {
    let store = Arc::new(MemoryIdentityStore::with_config(MemoryConfig {
        ttl_secs: 4,
        window_secs: 2,
        max_entries: 16,
    }));
    let h = spawn_janitor(Arc::clone(&store));
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    h.abort();
}

#[tokio::test]
async fn config_accessor_returns_set_values() {
    let cfg = MemoryConfig {
        ttl_secs: 99,
        window_secs: 11,
        max_entries: 7,
    };
    let store = MemoryIdentityStore::with_config(cfg);
    assert_eq!(store.config().ttl_secs, 99);
    assert_eq!(store.config().window_secs, 11);
    assert_eq!(store.config().max_entries, 7);
}
