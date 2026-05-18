#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::missing_panics_doc,
    clippy::similar_names,
    clippy::missing_const_for_fn,
    clippy::redundant_clone,
    clippy::manual_range_contains,
    clippy::needless_update,
    clippy::needless_range_loop,
    clippy::cast_lossless,
    clippy::cast_possible_wrap
)]
//! Phase 7 — cardinality / load behaviour for the audit emitter.
//!
//! Three scenarios, all using the lazy-connect `Database` stub so no
//! PostgreSQL instance is required.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use waf_engine::audit_emitter::{AuditCtx, AuditEmitter, AuditEmitterConfig, BroadcastSink, EmitOutcome, LiveEvent};
use waf_storage::Database;

#[derive(Debug, Default)]
struct CountingSink {
    count: AtomicU64,
}

impl CountingSink {
    fn arc() -> Arc<Self> {
        Arc::new(Self::default())
    }
    fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

impl BroadcastSink for CountingSink {
    fn try_broadcast(&self, _evt: &LiveEvent) {
        self.count.fetch_add(1, Ordering::Relaxed);
    }
}

fn stub_db() -> Arc<Database> {
    Arc::new(Database::connect_lazy("postgres://stub:stub@127.0.0.1:1/stub?sslmode=disable", 1).expect("connect_lazy"))
}

fn fast_cfg(channel: usize) -> AuditEmitterConfig {
    AuditEmitterConfig {
        enabled: true,
        window_secs: 60,
        max_keys: 200_000,
        channel_capacity: channel,
        gc_interval_secs: 60,
    }
}

#[tokio::test]
async fn scenario_a_single_ip_burst_produces_one_emit_per_window() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_cfg(64));

    let ctx = AuditCtx {
        host_code: "demo",
        client_ip: "203.0.113.7",
        method: "GET",
        path: "/",
    };

    let mut emitted = 0u64;
    let mut rate_limited = 0u64;
    for _ in 0..1_000 {
        match emitter.emit(&ctx, "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None) {
            EmitOutcome::Emitted => emitted += 1,
            EmitOutcome::RateLimited => rate_limited += 1,
            _ => {}
        }
    }

    assert_eq!(emitted, 1, "exactly one row should escape the 60s window");
    assert_eq!(rate_limited, 999, "the remaining 999 must hit the rate limit");
    assert_eq!(sink.count(), 1_000, "WS feed observes every detection (F1.5)");
}

#[tokio::test]
async fn scenario_b_unique_ips_fan_out_each_get_their_own_emit() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_cfg(4096));

    let mut emitted = 0u64;
    let mut dropped = 0u64;
    for i in 0..2_000 {
        let ip = format!("198.51.100.{}", i % 254 + 1);
        let ip_static: &'static str = Box::leak(ip.into_boxed_str());
        let ctx = AuditCtx {
            host_code: "demo",
            client_ip: ip_static,
            method: "GET",
            path: "/",
        };
        match emitter.emit(&ctx, "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None) {
            EmitOutcome::Emitted => emitted += 1,
            EmitOutcome::QueueFullDropped => dropped += 1,
            _ => {}
        }
    }

    // `i % 254 + 1` yields IPs 198.51.100.1..=198.51.100.254 — exactly 254
    // distinct values. Each first hit is `Emitted`, each subsequent hit on
    // the same IP within the 60s window must be `RateLimited`. Strict
    // assertion (M1 fix): no slack — the bucket logic should be exact.
    assert_eq!(emitted, 254, "expected exactly 254 unique-IP emits");
    assert_eq!(
        dropped, 0,
        "channel capacity 4096 must never overflow for 254 unique queues"
    );
}

#[tokio::test]
async fn scenario_c_mixed_burst_does_not_starve_unique_fanout() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_cfg(4096));

    // Hammer a single IP 5_000 times — only 1 row escapes the window.
    let hot_ctx = AuditCtx {
        host_code: "demo",
        client_ip: "192.0.2.42",
        method: "GET",
        path: "/",
    };
    for _ in 0..5_000 {
        emitter.emit(&hot_ctx, "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None);
    }

    // Fan out across 500 unique IPs — all should emit at least once.
    let mut unique_emits = 0u64;
    for i in 0..500 {
        let ip = format!("192.0.2.{}", (i % 254) + 1);
        let ip_static: &'static str = Box::leak(ip.into_boxed_str());
        let ctx = AuditCtx {
            host_code: "demo",
            client_ip: ip_static,
            method: "GET",
            path: "/",
        };
        if matches!(
            emitter.emit(&ctx, "BOT-RELAY-TOR-001", "tor_exit", "log_only", None),
            EmitOutcome::Emitted
        ) {
            unique_emits += 1;
        }
    }

    let snap = emitter.metrics_snapshot();
    assert!(
        unique_emits >= 200,
        "fan-out must not be starved by hot-IP burst — got {unique_emits}"
    );
    assert!(
        snap.rate_limited >= 4_999,
        "hot IP must rate-limit {}",
        snap.rate_limited
    );
}

#[tokio::test]
async fn memory_residual_stays_bounded_after_unique_emits() {
    let sink = CountingSink::arc();
    let cfg = AuditEmitterConfig {
        enabled: true,
        window_secs: 1,
        max_keys: 1_000,
        channel_capacity: 4096,
        gc_interval_secs: 1,
        ..AuditEmitterConfig::default()
    };
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, cfg);

    for i in 0..5_000 {
        let ip = format!("10.10.{}.{}", (i / 256) % 256, i % 256);
        let ip_static: &'static str = Box::leak(ip.into_boxed_str());
        let ctx = AuditCtx {
            host_code: "demo",
            client_ip: ip_static,
            method: "GET",
            path: "/",
        };
        emitter.emit(&ctx, "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None);
    }

    // Wait for at least one janitor pass after the window expires (1s window
    // + small slop). After GC the bucket count must be bounded by max_keys.
    tokio::time::sleep(Duration::from_millis(2_500)).await;

    assert!(
        emitter.bucket_count() <= 1_000,
        "max_keys enforcement failed: {}",
        emitter.bucket_count()
    );
}
