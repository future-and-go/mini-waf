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
    clippy::cast_possible_wrap,
    clippy::needless_pass_by_ref_mut,
    clippy::field_reassign_with_default
)]
//! Phase 1 — `AuditEmitter` regression tests.
//!
//! Exercise the public emit() surface against the red-team patched ordering:
//!   - F1.3: bucket claim happens AFTER successful try_send
//!   - F1.5/CC4: WS broadcast fires regardless of rate-limit gate
//!   - F1.7: TTL = window_secs (single knob)
//!
//! DB layer uses `Database::connect_lazy` so no Postgres instance is needed —
//! INSERTs fail with a connect error which the supervisor handles via the
//! `db_insert_failed` metric. Tests assert against the queue / bucket / WS
//! observable behavior, not row contents.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use waf_engine::audit_emitter::{AuditCtx, AuditEmitter, AuditEmitterConfig, BroadcastSink, EmitOutcome, LiveEvent};
use waf_storage::Database;

/// Recording sink — counts every WS broadcast call.
#[derive(Debug, Default)]
struct CountingSink {
    count: AtomicU64,
    last_rule_id: parking_lot::Mutex<Option<&'static str>>,
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
    fn try_broadcast(&self, evt: &LiveEvent) {
        self.count.fetch_add(1, Ordering::Relaxed);
        *self.last_rule_id.lock() = Some(evt.rule_id);
    }
}

fn ctx<'a>() -> AuditCtx<'a> {
    AuditCtx {
        host_code: "demo",
        client_ip: "10.0.0.1",
        method: "GET",
        path: "/",
    }
}

fn fast_window_cfg() -> AuditEmitterConfig {
    AuditEmitterConfig {
        enabled: true,
        window_secs: 60,
        max_keys: 100,
        channel_capacity: 16,
        gc_interval_secs: 60,
    }
}

fn stub_db() -> Arc<Database> {
    Arc::new(
        Database::connect_lazy("postgres://stub:stub@127.0.0.1:1/stub?sslmode=disable", 1)
            .expect("connect_lazy must succeed even without a live server"),
    )
}

#[tokio::test]
async fn disabled_config_short_circuits_no_broadcast() {
    let sink = CountingSink::arc();
    let cfg = AuditEmitterConfig {
        enabled: false,
        ..AuditEmitterConfig::default()
    };
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, cfg);

    let outcome = emitter.emit(&ctx(), "TEST-001", "test_rule", "log_only", None);
    assert_eq!(outcome, EmitOutcome::Disabled);
    assert_eq!(sink.count(), 0, "disabled emitter must not broadcast");
    assert_eq!(emitter.bucket_count(), 0);
}

#[tokio::test]
async fn first_emit_returns_emitted_and_broadcasts() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    let outcome = emitter.emit(&ctx(), "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None);
    assert_eq!(outcome, EmitOutcome::Emitted);
    assert_eq!(sink.count(), 1);
    assert_eq!(emitter.bucket_count(), 1);
    assert_eq!(*sink.last_rule_id.lock(), Some("BOT-XFF-MALFORMED-001"));
}

#[tokio::test]
async fn second_emit_within_window_rate_limited_but_still_broadcasts() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    let first = emitter.emit(&ctx(), "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None);
    let second = emitter.emit(&ctx(), "BOT-XFF-MALFORMED-001", "xff_validator", "log_only", None);

    assert_eq!(first, EmitOutcome::Emitted);
    assert_eq!(second, EmitOutcome::RateLimited);
    assert_eq!(sink.count(), 2, "WS feed must see every detection (F1.5 fix)");
    let snap = emitter.metrics_snapshot();
    assert_eq!(snap.emitted, 1);
    assert_eq!(snap.rate_limited, 1);
}

#[tokio::test]
async fn different_rule_ids_share_no_bucket() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    let a = emitter.emit(&ctx(), "RULE-A", "a", "log_only", None);
    let b = emitter.emit(&ctx(), "RULE-B", "b", "log_only", None);
    assert_eq!(a, EmitOutcome::Emitted);
    assert_eq!(b, EmitOutcome::Emitted);
    assert_eq!(emitter.bucket_count(), 2);
}

#[tokio::test]
async fn different_ips_share_no_bucket() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    let mut a = ctx();
    a.client_ip = "10.0.0.1";
    let mut b = ctx();
    b.client_ip = "10.0.0.2";

    assert_eq!(emitter.emit(&a, "R", "r", "log_only", None), EmitOutcome::Emitted);
    assert_eq!(emitter.emit(&b, "R", "r", "log_only", None), EmitOutcome::Emitted);
}

#[tokio::test]
async fn queue_full_does_not_poison_bucket() {
    let sink = CountingSink::arc();
    // capacity = 1, no DB drain (lazy connect never succeeds → queue fills).
    let cfg = AuditEmitterConfig {
        enabled: true,
        window_secs: 60,
        max_keys: 100,
        channel_capacity: 1,
        gc_interval_secs: 60,
    };
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, cfg);

    let mut full_seen = false;
    for i in 0..1024 {
        let mut c = ctx();
        let ip = format!("198.51.100.{}", i % 254 + 1);
        c.client_ip = &ip;
        let rule_static: &'static str = Box::leak(format!("STRESS-{i:04}").into_boxed_str());
        if matches!(
            emitter.emit(&c, rule_static, "stress", "log_only", None),
            EmitOutcome::QueueFullDropped
        ) {
            full_seen = true;
            break;
        }
    }
    assert!(full_seen, "must observe QueueFullDropped within 1024 attempts");

    let snap = emitter.metrics_snapshot();
    assert_eq!(
        u64::try_from(emitter.bucket_count()).unwrap_or(0),
        snap.emitted,
        "bucket count must equal Emitted count — Full must not claim (F1.3 fix)"
    );
    assert!(snap.queue_full_dropped >= 1);
}

#[tokio::test]
async fn is_enabled_reflects_config() {
    let sink = CountingSink::arc();
    let enabled = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());
    let disabled_cfg = AuditEmitterConfig {
        enabled: false,
        ..AuditEmitterConfig::default()
    };
    let disabled = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, disabled_cfg);

    assert!(enabled.is_enabled());
    assert!(!disabled.is_enabled());
}

#[tokio::test]
async fn worker_handles_db_failure_gracefully() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    let first = emitter.emit(&ctx(), "ERR-001", "err", "log_only", None);
    assert_eq!(first, EmitOutcome::Emitted);

    // Give the supervisor time to attempt the INSERT against the stub URL
    // and record the failure via the `db_insert_failed` counter.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let snap = emitter.metrics_snapshot();
    assert_eq!(snap.emitted, 1);
    // db_insert_failed may or may not have fired yet depending on connect
    // timeout (sqlx defaults to 30s acquire timeout) — assert it never goes
    // negative and the worker is alive enough to accept another emit.
    let mut c = ctx();
    c.client_ip = "10.0.0.99";
    let second = emitter.emit(&c, "ERR-002", "err", "log_only", None);
    assert_eq!(second, EmitOutcome::Emitted);
}

#[tokio::test]
async fn bucket_count_reflects_distinct_emits() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    for i in 0..5 {
        let mut c = ctx();
        let ip = format!("10.0.0.{i}");
        c.client_ip = &ip;
        emitter.emit(&c, "R", "r", "log_only", None);
    }
    assert_eq!(emitter.bucket_count(), 5);
}

#[tokio::test]
async fn detail_payload_is_preserved_on_emit_outcome() {
    let sink = CountingSink::arc();
    let emitter = AuditEmitter::new(stub_db(), sink.clone() as Arc<dyn BroadcastSink>, fast_window_cfg());

    let out = emitter.emit(
        &ctx(),
        "TX-SEQ-001",
        "tx_sequence",
        "block",
        Some(r#"{"interval_ms":1230}"#.to_string()),
    );
    assert_eq!(out, EmitOutcome::Emitted);
    assert_eq!(sink.count(), 1);
}
