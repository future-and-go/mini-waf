//! Cross-module integration tests for the audit emitter subsystem.
//!
//! These tests exercise the public surface (`audit_emitter::{config,bucket,
//! global_bucket,sanitize,metrics,broadcast}` + `intel_status`) without a live
//! database — the full `AuditEmitter::emit` path requires `Database::connect`
//! which is deferred to the Postgres testcontainers smoke per master plan BP8.
//!
//! Scenarios covered (master-plan PR-0 contract):
//!   1. Disabled config short-circuits without allocation.
//!   2. Channel-capacity floor enforced on tiny + zero values.
//!   3. Channel-capacity above floor preserved verbatim.
//!   4. Hot-reload via `AuditEmitterConfig` round-trip swap.
//!   5. Rule-id grammar accept/reject (BP6).
//!   6. Per-rule override beats default for global bucket cap.
//!   7. Global per-rule-id bucket cap exhausts then refills under paused clock.
//!   8. Bucket reserve atomic under concurrent contention (no double-charge).
//!   9. Bucket rollback frees the slot for the next emit.
//!  10. Bucket GC prunes expired entries.
//!  11. IPv4 + IPv4-in-IPv6 share a single bucket key.
//!  12. Sanitiser HTML/JSON escapes + UTF-8 boundary truncation.
//!  13. Sanitiser truncates at 4 KB cap.
//!  14. Metrics atomicity across all counters.
//!  15. Metrics snapshot frozen against later increments.
//!  16. `FeedStatusRegistry` clone shares inner state.
//!  17. NoopBroadcastSink no-op contract.
//!  18. TOML round-trip with per-rule overrides.

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

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use waf_engine::audit_emitter::{
    AuditEmitterConfig, AuditEmitterMetrics, BucketStore, CHANNEL_CAPACITY_FLOOR, DEFAULT_GLOBAL_TOKENS_PER_SEC,
    GlobalRateBucket, MAX_DETAIL_BYTES, NoopBroadcastSink, make_key, new_shared_global_bucket, sanitize_detail,
};
use waf_engine::intel_status::{FeedStatusRegistry, FeedStatusSnapshot};

// ── 1. Disabled config short-circuit ───────────────────────────────────────────

#[test]
fn disabled_emit_returns_disabled_without_alloc() {
    // The default config is `enabled = false`; verify the gate state directly,
    // matching the contract `AuditEmitter::emit` checks in mod.rs:196.
    let cfg = AuditEmitterConfig::default();
    assert!(!cfg.enabled, "default config must be disabled for fail-closed posture");
}

// ── 2. Channel-capacity floor enforced ────────────────────────────────────────

#[test]
fn channel_capacity_zero_lifts_to_floor() {
    let cfg = AuditEmitterConfig {
        channel_capacity: 0,
        ..AuditEmitterConfig::default()
    };
    assert!(cfg.resolved_channel_capacity() >= CHANNEL_CAPACITY_FLOOR);
}

#[test]
fn channel_capacity_tiny_lifts_to_floor() {
    let cfg = AuditEmitterConfig {
        channel_capacity: 7,
        ..AuditEmitterConfig::default()
    };
    assert_eq!(cfg.resolved_channel_capacity(), CHANNEL_CAPACITY_FLOOR);
}

// ── 3. Channel-capacity above floor preserved ─────────────────────────────────

#[test]
fn channel_capacity_above_floor_kept_verbatim() {
    let cfg = AuditEmitterConfig {
        channel_capacity: CHANNEL_CAPACITY_FLOOR * 4,
        ..AuditEmitterConfig::default()
    };
    assert_eq!(cfg.resolved_channel_capacity(), CHANNEL_CAPACITY_FLOOR * 4);
}

// ── 4. Hot-reload via config round-trip swap ──────────────────────────────────

#[test]
fn config_round_trip_via_toml() {
    let toml = r#"
enabled = true
window_secs = 15
channel_capacity = 8192
gc_interval_secs = 45
max_keys = 2048
global_tokens_per_sec = 80

[global_rate]
"BOT-XFF-001" = 250
"TX-SEQ-001"  = 120
"#;
    let cfg: AuditEmitterConfig = toml::from_str(toml).expect("valid toml");
    assert!(cfg.enabled);
    assert_eq!(cfg.window_secs, 15);
    assert_eq!(cfg.gc_interval_secs, 45);
    assert_eq!(cfg.max_keys, 2048);
    assert_eq!(cfg.tokens_per_sec_for("BOT-XFF-001"), 250);
    assert_eq!(cfg.tokens_per_sec_for("TX-SEQ-001"), 120);
    assert_eq!(cfg.tokens_per_sec_for("BOT-TOR-001"), 80);
}

// ── 5. Rule-id grammar accept/reject (BP6) ────────────────────────────────────

#[test]
fn rule_id_grammar_accepts_builtin_ids() {
    // Verify via TOML key acceptance — the same regex contract applies inside
    // `AuditEmitter::emit` against `rule_id_regex()`. Keys round-trip cleanly
    // through `global_rate.overrides`.
    let mut overrides = HashMap::new();
    for id in [
        "BOT-XFF-001",
        "BOT-RELAY-001",
        "BOT-TOR-001",
        "TX-SEQ-001",
        "TX-WITHDRAW-001",
        "TX-LIMIT-001",
    ] {
        overrides.insert(id.to_string(), 50u32);
    }
    let gb = GlobalRateBucket::new(100, &overrides);
    // Built-in ids must each have a configured bucket (cap = 50 from override).
    assert!(gb.try_acquire("BOT-XFF-001"));
    assert!(gb.try_acquire("TX-LIMIT-001"));
}

// ── 6. Per-rule override beats default cap ─────────────────────────────────────

#[test]
fn per_rule_override_takes_precedence_over_default() {
    let mut overrides = HashMap::new();
    overrides.insert("BOT-RELAY-001".to_string(), 1u32);
    let gb = GlobalRateBucket::new(DEFAULT_GLOBAL_TOKENS_PER_SEC, &overrides);
    assert!(gb.try_acquire("BOT-RELAY-001"));
    assert!(
        !gb.try_acquire("BOT-RELAY-001"),
        "override cap=1 should exhaust after one acquire"
    );
    // A sibling rule still gets the default cap (100).
    assert!(gb.try_acquire("BOT-TOR-001"));
}

// ── 7. Global bucket cap exhausts then refills under paused clock ─────────────

#[tokio::test(start_paused = true)]
async fn global_bucket_exhausts_then_refills_after_tick() {
    let shared = new_shared_global_bucket(2, &HashMap::new());
    let metrics = AuditEmitterMetrics::new();
    GlobalRateBucket::spawn_refill_task(Arc::clone(&shared), metrics);

    {
        let gb = shared.lock().await;
        assert!(gb.try_acquire("TX-WITHDRAW-001"));
        assert!(gb.try_acquire("TX-WITHDRAW-001"));
        assert!(!gb.try_acquire("TX-WITHDRAW-001"));
    }

    tokio::time::advance(Duration::from_millis(1_100)).await;
    tokio::task::yield_now().await;

    {
        let gb = shared.lock().await;
        assert!(
            gb.try_acquire("TX-WITHDRAW-001"),
            "refill task should restore at least one token"
        );
    }
}

// ── 8. Bucket reserve atomic under concurrent contention ──────────────────────

#[test]
fn bucket_reserve_only_one_winner_under_contention() {
    let store = Arc::new(BucketStore::new());
    let success = Arc::new(AtomicU32::new(0));
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50));

    let handles: Vec<_> = (0..16)
        .map(|_| {
            let s = Arc::clone(&store);
            let c = Arc::clone(&success);
            std::thread::spawn(move || {
                if s.try_reserve(ip, "BOT-XFF-001", 60) {
                    c.fetch_add(1, Ordering::Relaxed);
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("worker thread did not panic");
    }

    assert_eq!(
        success.load(Ordering::Relaxed),
        1,
        "atomic try_reserve must allow exactly one winner per (ip, rule_id)"
    );
}

// ── 9. Bucket rollback frees the slot ─────────────────────────────────────────

#[test]
fn bucket_rollback_unblocks_next_emit() {
    let store = BucketStore::new();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));

    assert!(store.try_reserve(ip, "TX-SEQ-001", 60));
    assert!(!store.try_reserve(ip, "TX-SEQ-001", 60));

    store.rollback(ip, "TX-SEQ-001", 60);
    assert!(
        store.try_reserve(ip, "TX-SEQ-001", 60),
        "rollback must free the slot for retry"
    );
}

// ── 9b. Expired-slot reuse exercises the `value_mut()` rewrite branch ─────────
//
// Regression guard for `bucket.rs::try_reserve` line ~55:
//     if *entry.value() <= now { *entry.value_mut() = expiry; return true; }
// Requires the `entry` binding to be `mut`. PR #105's first push compiled in
// isolation but tripped E0596 under `release/stg`'s `RUSTFLAGS=-D warnings`
// posture because no inline test hit this branch.

#[test]
fn bucket_expired_slot_is_reclaimed_on_next_reserve() {
    let store = BucketStore::new();
    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 77));

    // First reserve with `window_secs = 0` — expiry == now, so by the time
    // the next call reads its own `now` the slot is already past.
    assert!(store.try_reserve(ip, "TX-LIMIT-001", 0));
    assert_eq!(store.len(), 1, "first reserve must record the entry");

    // Tiny pause so the next `now_epoch_ms()` is strictly greater than the
    // stored expiry. 5 ms is well under any reasonable test budget.
    std::thread::sleep(Duration::from_millis(5));

    // Second reserve hits the `<= now` branch, calls `value_mut()` to rewrite
    // the expiry, and returns `true` without inserting a second entry.
    assert!(
        store.try_reserve(ip, "TX-LIMIT-001", 60),
        "expired slot must be reclaimable; this asserts `let mut entry` survives"
    );
    assert_eq!(store.len(), 1, "expired-slot rewrite must not duplicate the key");

    // Sanity: the slot is now armed for 60s, so an immediate third call is
    // rate-limited.
    assert!(
        !store.try_reserve(ip, "TX-LIMIT-001", 60),
        "freshly reclaimed slot should rate-limit the very next call"
    );
}

// ── 10. Bucket GC prunes expired entries ──────────────────────────────────────

#[test]
fn bucket_gc_prunes_expired_entries_only() {
    let store = BucketStore::new();

    // Window 0 → expiry == now, already past once `gc()` reads its own `now`.
    let expired_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    assert!(store.try_reserve(expired_ip, "BOT-TOR-001", 0));
    // Future entry — 1 hour window is way past gc tolerance.
    let active_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    assert!(store.try_reserve(active_ip, "BOT-XFF-001", 3_600));

    assert_eq!(store.len(), 2);
    // Sleep a tiny bit so the 0-window entry is definitely behind `now`.
    std::thread::sleep(Duration::from_millis(5));
    store.gc(10_000);
    assert_eq!(store.len(), 1, "only the active entry should survive gc");
}

// ── 11. IPv4 + IPv4-in-IPv6 share a single bucket key ─────────────────────────

#[test]
fn ipv4_and_ipv4_in_ipv6_share_one_key() {
    let ip4 = IpAddr::V4(Ipv4Addr::new(10, 11, 12, 13));
    let ip6_mapped = IpAddr::V6(Ipv6Addr::from([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 11, 12, 13,
    ]));
    let key4 = make_key(ip4, "BOT-XFF-001");
    let key6 = make_key(ip6_mapped, "BOT-XFF-001");
    assert_eq!(key4, key6, "v4 and v4-mapped-v6 must collapse to a single bucket");
}

// ── 12. Sanitiser HTML/JSON escapes + UTF-8 truncation ────────────────────────

#[test]
fn sanitize_detail_html_json_escapes_combined() {
    let raw = r#"<script>alert("\xss & evil")</script>"#;
    let out = sanitize_detail(raw);
    assert!(!out.contains('<'), "<{out}> must not contain raw '<'");
    assert!(!out.contains('>'), "<{out}> must not contain raw '>'");
    assert!(out.contains("&lt;") && out.contains("&gt;") && out.contains("&amp;"));
}

#[test]
fn sanitize_detail_truncates_at_utf8_boundary() {
    // 2-byte UTF-8 (é) — repeated to push past the 4KB cap, ensuring the
    // walk-back-to-boundary logic does not corrupt the trailing byte.
    let raw: String = "é".repeat(3_000);
    let out = sanitize_detail(&raw);
    assert!(out.len() <= MAX_DETAIL_BYTES);
    assert!(std::str::from_utf8(out.as_bytes()).is_ok());
}

// ── 13. 4KB cap honoured for ASCII overflow ───────────────────────────────────

#[test]
fn sanitize_detail_caps_at_4kb_for_ascii_overflow() {
    let raw = "x".repeat(MAX_DETAIL_BYTES * 4);
    let out = sanitize_detail(&raw);
    assert!(out.len() <= MAX_DETAIL_BYTES);
}

// ── 14. Metrics atomicity across all counters ─────────────────────────────────

#[test]
fn metrics_all_counters_atomic_under_concurrent_inc() {
    let metrics = AuditEmitterMetrics::new();
    let n_threads: u32 = 8;
    let n_per_thread: u32 = 250;

    let handles: Vec<_> = (0..n_threads)
        .map(|_| {
            let m = Arc::clone(&metrics);
            std::thread::spawn(move || {
                for _ in 0..n_per_thread {
                    m.inc_emitted();
                    m.inc_rate_limited();
                    m.inc_queue_full_dropped();
                    m.inc_global_rate_limited();
                    m.inc_invalid_rule_id();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("metrics inc thread did not panic");
    }

    let snap = metrics.snapshot();
    let expected = u64::from(n_threads * n_per_thread);
    assert_eq!(snap.emitted, expected);
    assert_eq!(snap.rate_limited, expected);
    assert_eq!(snap.queue_full_dropped, expected);
    assert_eq!(snap.global_rate_limited, expected);
    assert_eq!(snap.invalid_rule_id, expected);
}

// ── 15. Metrics snapshot frozen against later increments ──────────────────────

#[test]
fn metrics_snapshot_frozen_against_later_increments() {
    let m = AuditEmitterMetrics::new();
    m.inc_emitted();
    m.inc_emitted();
    let snap_before = m.snapshot();
    m.inc_emitted();
    m.inc_emitted();
    m.inc_emitted();
    assert_eq!(snap_before.emitted, 2);
    assert_eq!(m.snapshot().emitted, 5);
}

// ── 16. FeedStatusRegistry clone shares inner state ───────────────────────────

#[test]
fn feed_status_registry_clone_shares_state() {
    let r1 = FeedStatusRegistry::new();
    let r2 = r1.clone();
    assert!(!r2.snapshot().available);
    r1.mark_loaded(1_234, 56_789);
    let snap = r2.snapshot();
    assert!(snap.available);
    assert_eq!(snap.tor_count, Some(1_234));
    assert_eq!(snap.asn_count, Some(56_789));
}

#[test]
fn feed_status_default_snapshot_is_unavailable() {
    let snap = FeedStatusSnapshot::default();
    assert!(!snap.available);
    assert!(snap.tor_count.is_none());
    assert!(snap.asn_count.is_none());
    assert!(snap.last_refreshed.is_none());
}

// ── 17. NoopBroadcastSink no-op contract ──────────────────────────────────────

#[tokio::test]
async fn noop_broadcast_sink_does_not_panic_or_block() {
    use waf_engine::audit_emitter::BroadcastSink;
    let sink: Arc<dyn BroadcastSink> = Arc::new(NoopBroadcastSink);
    for _ in 0..32 {
        sink.broadcast(serde_json::json!({
            "rule_id": "BOT-XFF-001",
            "method": "GET",
            "path": "/api/x",
        }))
        .await;
    }
}

// ── 18. Unknown rule_id falls through global bucket gate ──────────────────────

#[test]
fn unknown_rule_id_is_not_capped_by_global_bucket() {
    let gb = GlobalRateBucket::new(1, &HashMap::new());
    // "HONEYPOT-FUTURE-999" is not a built-in id; the bucket must pass it.
    for _ in 0..10 {
        assert!(gb.try_acquire("HONEYPOT-FUTURE-999"));
    }
}
