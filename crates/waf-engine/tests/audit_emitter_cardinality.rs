//! Cardinality / capacity-bound integration tests for the audit emitter.
//!
//! Validates the layer-1 bucket store under bursty, IP-rotating, and
//! cap-exceeded workloads. Goal: prove that the `max_keys` eviction policy
//! and atomic `try_reserve` semantics hold under load without unbounded
//! memory growth.
//!
//! Postgres testcontainers smoke is intentionally NOT in this file — that
//! coverage lands in a follow-up once the testcontainers harness is ready.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::cast_possible_truncation
)]

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use waf_engine::audit_emitter::BucketStore;

/// Build a unique IPv4 from a 32-bit counter — covers the full v4 space
/// without overlap so each iteration creates a fresh bucket key.
fn ipv4_from_index(i: u32) -> IpAddr {
    IpAddr::V4(Ipv4Addr::from(i))
}

// ── 1. Single-IP burst: 10k hits → exactly one reservation ────────────────────

#[test]
fn single_ip_burst_results_in_one_reservation() {
    let store = BucketStore::new();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1));

    let mut wins = 0u32;
    for _ in 0..10_000 {
        if store.try_reserve(ip, "BOT-XFF-001", 60) {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "single ip burst must collapse to one reservation");
    assert_eq!(store.len(), 1, "bucket count must stay at one");
}

// ── 2. 10k unique IPs fan-out: every reserve wins, store grows linearly ───────

#[test]
fn fan_out_10k_unique_ips_each_wins_once() {
    let store = BucketStore::new();
    const N: u32 = 10_000;

    for i in 0..N {
        assert!(store.try_reserve(ipv4_from_index(i), "TX-SEQ-001", 60));
    }
    assert_eq!(store.len(), N as usize);

    // Second pass: every IP is now rate-limited.
    let mut second_pass_blocked = 0u32;
    for i in 0..N {
        if !store.try_reserve(ipv4_from_index(i), "TX-SEQ-001", 60) {
            second_pass_blocked += 1;
        }
    }
    assert_eq!(second_pass_blocked, N, "second pass must be blocked for every key");
}

// ── 3. Bucket-store growth bounded under sustained insert (cardinality) ───────
//
// We cannot measure process RSS portably from a unit test; instead we assert
// that after eviction the store stays inside a hard cap. The RSS-delta < 5 MB
// claim from the master plan translates to "BucketStore never exceeds
// max_keys after gc", since each entry is a fixed-size `(u128, &'static str,
// u64)` tuple (~32 bytes) — 10k entries ≈ 320 KB upper bound on the heap.

#[test]
fn gc_caps_bucket_store_below_max_keys_under_overflow() {
    let store = BucketStore::new();
    let max_keys = 1_000usize;
    let overflow_n = 5_000u32;

    // Drive overflow through the public `try_reserve` API (no direct DashMap
    // access). All entries share the same long window so the gc pass treats
    // them as "active but over-cap" and falls into the LRU-by-expiry branch.
    for i in 0..overflow_n {
        assert!(store.try_reserve(ipv4_from_index(i), "TX-LIMIT-001", 600));
    }
    assert_eq!(store.len(), overflow_n as usize);

    store.gc(max_keys);
    assert!(
        store.len() <= max_keys,
        "gc must enforce max_keys cap; got {} > {}",
        store.len(),
        max_keys
    );
}

// ── 4. Mixed burst (single-IP attacker + 1k legit IPs) ────────────────────────

#[test]
fn mixed_burst_attacker_does_not_starve_legit_keys() {
    let store = BucketStore::new();
    let attacker = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));

    // Attacker tries 1000 times against one rule — only first wins.
    for _ in 0..1_000 {
        let _ = store.try_reserve(attacker, "BOT-RELAY-001", 60);
    }

    // 1000 legit IPs each emit once against a different rule — all should pass.
    let mut legit_wins = 0u32;
    for i in 0..1_000u32 {
        if store.try_reserve(ipv4_from_index(i + 10_000), "TX-WITHDRAW-001", 60) {
            legit_wins += 1;
        }
    }
    assert_eq!(
        legit_wins, 1_000,
        "attacker on one rule must not block legit traffic on another"
    );
    assert_eq!(store.len(), 1_001, "exactly one attacker bucket + 1000 legit buckets");
}

// ── 5. Max-keys eviction under concurrent insert (atomic + bounded) ───────────

#[test]
fn max_keys_eviction_under_concurrent_insert() {
    let store = Arc::new(BucketStore::new());
    let max_keys = 256usize;
    let workers = 8usize;
    let per_worker = 1_000u32;
    let inserts = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..workers)
        .map(|w| {
            let s = Arc::clone(&store);
            let n = Arc::clone(&inserts);
            std::thread::spawn(move || {
                let base = u32::try_from(w).unwrap_or(0).saturating_mul(1_000_000);
                for i in 0..per_worker {
                    if s.try_reserve(ipv4_from_index(base.wrapping_add(i)), "BOT-TOR-001", 60) {
                        n.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker did not panic");
    }

    // Before gc the store holds workers*per_worker entries (all unique IPs).
    let inserted = u32::try_from(workers).unwrap_or(0).saturating_mul(per_worker);
    assert_eq!(inserts.load(Ordering::Relaxed), u64::from(inserted));

    store.gc(max_keys);
    assert!(
        store.len() <= max_keys,
        "post-gc store length {} must be ≤ max_keys {}",
        store.len(),
        max_keys
    );
}
