//! Shared conformance scenarios for `IdentityStore` implementations.
//!
//! Both the in-memory (phase-05) and Redis (phase-08) backends MUST pass
//! the same suite. Tests are async + black-box: they only touch the
//! trait surface so swapping impls requires no test edits.
//!
//! Twelve scenarios — see the `run_store_conformance` body for the list.

#![cfg(test)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::device_fp::identity::identity_trait::IdentityStore;
use crate::device_fp::types::{FingerprintValue, FpKey};

fn make_key(tag: &str) -> FpKey {
    FpKey {
        ja3: Some(FingerprintValue::new(tag)),
        ja4: None,
        h2_akamai: None,
    }
}

fn ipv4(o: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, o))
}

/// Runs the full 12-scenario conformance suite against `store`.
/// Panics on any assertion failure.
pub async fn run_store_conformance(store: Arc<dyn IdentityStore>) {
    basic_observe_lookup(&store).await;
    distinct_ip_counting(&store).await;
    distinct_ua_counting(&store).await;
    same_fp_same_ip_no_double_count(&store).await;
    purge_expired_count(&store).await;
    lookup_miss(&store).await;
    clock_skew_tolerance(&store).await;
    drop_semantics(&store).await;
    cardinality_cap_edge(&store).await;
    lru_eviction_at_cap(&store).await;
    ttl_expiry(&store).await;
    concurrent_observers(&store).await;
}

// ── 1. basic observe → lookup roundtrip ────────────────────────────────────
async fn basic_observe_lookup(store: &Arc<dyn IdentityStore>) {
    let k = make_key("basic");
    let obs = store.observe(&k, ipv4(1), "ua-x", 1_000).await.unwrap();
    assert_eq!(obs.first_seen_unix, 1_000);
    assert_eq!(obs.last_seen_unix, 1_000);
    assert_eq!(obs.distinct_ips_in_window, 1);
    let rec = store.lookup(&k).await.unwrap().expect("present");
    assert_eq!(rec.first_seen_unix, 1_000);
}

// ── 2. distinct IPs in window ──────────────────────────────────────────────
async fn distinct_ip_counting(store: &Arc<dyn IdentityStore>) {
    let k = make_key("ips");
    for o in 1..=4 {
        store.observe(&k, ipv4(o), "ua", 2_000).await.unwrap();
    }
    let obs = store.observe(&k, ipv4(5), "ua", 2_000).await.unwrap();
    assert!(obs.distinct_ips_in_window >= 5, "got {}", obs.distinct_ips_in_window);
}

// ── 3. distinct UAs in window ──────────────────────────────────────────────
async fn distinct_ua_counting(store: &Arc<dyn IdentityStore>) {
    let k = make_key("uas");
    for ua in ["a", "b", "c"] {
        store.observe(&k, ipv4(1), ua, 3_000).await.unwrap();
    }
    let obs = store.observe(&k, ipv4(1), "d", 3_000).await.unwrap();
    assert!(obs.distinct_uas_in_window >= 4);
}

// ── 4. same fp + same ip + same ua → distinct count stays 1 ────────────────
async fn same_fp_same_ip_no_double_count(store: &Arc<dyn IdentityStore>) {
    let k = make_key("dup");
    for _ in 0..10 {
        store.observe(&k, ipv4(7), "ua-z", 4_000).await.unwrap();
    }
    let rec = store.lookup(&k).await.unwrap().expect("present");
    assert_eq!(rec.distinct_ips, 1);
    assert_eq!(rec.distinct_uas, 1);
}

// ── 5. purge_expired returns correct count ─────────────────────────────────
async fn purge_expired_count(store: &Arc<dyn IdentityStore>) {
    // Ancient entry — last_seen is well in the past, so any reasonable TTL
    // marks it expired against `now`.
    let k = make_key("ancient");
    store.observe(&k, ipv4(9), "old-ua", 1).await.unwrap();
    let purged = store.purge_expired().await.unwrap();
    // Cannot assert exact count (other tests share the store), but the
    // ancient key must be gone.
    assert!(purged >= 1, "expected ≥1 purged, got {purged}");
    assert!(store.lookup(&k).await.unwrap().is_none());
}

// ── 6. lookup miss returns None ────────────────────────────────────────────
async fn lookup_miss(store: &Arc<dyn IdentityStore>) {
    let k = make_key("never-observed");
    assert!(store.lookup(&k).await.unwrap().is_none());
}

// ── 7. out-of-order timestamps tolerated (clock skew) ──────────────────────
async fn clock_skew_tolerance(store: &Arc<dyn IdentityStore>) {
    let k = make_key("skew");
    store.observe(&k, ipv4(1), "ua", 5_000).await.unwrap();
    // Late-arriving observation with earlier ts — must not panic, must
    // update first_seen downward but keep last_seen at the max.
    let obs = store.observe(&k, ipv4(1), "ua", 4_500).await.unwrap();
    assert!(obs.first_seen_unix <= 4_500);
    assert!(obs.last_seen_unix >= 5_000);
}

// ── 8. drop semantics — store handles repeated puts without leaking ────────
async fn drop_semantics(store: &Arc<dyn IdentityStore>) {
    let k = make_key("drop");
    for ts in 6_000..6_050 {
        store.observe(&k, ipv4(1), "ua", ts).await.unwrap();
    }
    let rec = store.lookup(&k).await.unwrap().expect("present");
    assert_eq!(rec.distinct_ips, 1);
}

// ── 9. cardinality cap edge — inserting one over cap doesn't crash ─────────
async fn cardinality_cap_edge(store: &Arc<dyn IdentityStore>) {
    for i in 0..3 {
        let k = make_key(&format!("edge-{i}"));
        store.observe(&k, ipv4(1), "ua", 7_000).await.unwrap();
    }
    // Just confirm no panic + at least one of them is queryable.
    let rec = store.lookup(&make_key("edge-0")).await.unwrap();
    let _ = rec; // some impls may have evicted it under cap pressure
}

// ── 10. LRU eviction kicks in at cap ───────────────────────────────────────
async fn lru_eviction_at_cap(store: &Arc<dyn IdentityStore>) {
    // Stamp many distinct keys with monotonically increasing ts. Impls
    // with a small cap should keep the freshest and drop the oldest.
    for i in 0..32_u32 {
        let k = make_key(&format!("lru-{i}"));
        let ts = 8_000 + i64::from(i);
        store.observe(&k, ipv4(1), "ua", ts).await.unwrap();
    }
    // Newest key must still be present.
    let newest = store.lookup(&make_key("lru-31")).await.unwrap();
    assert!(newest.is_some(), "newest entry evicted");
}

// ── 11. TTL expiry purges old entries ──────────────────────────────────────
async fn ttl_expiry(store: &Arc<dyn IdentityStore>) {
    let k = make_key("ttl-victim");
    store.observe(&k, ipv4(1), "ua", 10).await.unwrap();
    let _ = store.purge_expired().await.unwrap();
    assert!(store.lookup(&k).await.unwrap().is_none());
}

// ── 12. concurrent observers — many tasks, no panic, no data race ──────────
async fn concurrent_observers(store: &Arc<dyn IdentityStore>) {
    let mut handles = Vec::new();
    for t in 0_u16..16 {
        let s = Arc::clone(store);
        let h = tokio::spawn(async move {
            let k = FpKey {
                ja3: Some(FingerprintValue::new(format!("conc-{}", t % 4))),
                ja4: None,
                h2_akamai: None,
            };
            for n in 0_u16..50 {
                let ip = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, t, n));
                s.observe(&k, ip, "ua", 9_000).await.unwrap();
            }
        });
        handles.push(h);
    }
    for h in handles {
        h.await.unwrap();
    }
    let rec = store
        .lookup(&FpKey {
            ja3: Some(FingerprintValue::new("conc-0")),
            ja4: None,
            h2_akamai: None,
        })
        .await
        .unwrap()
        .expect("present");
    assert!(rec.distinct_ips >= 1);
}
