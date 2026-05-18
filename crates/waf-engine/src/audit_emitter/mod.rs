//! Shared audit emission layer bridging detection modules → `security_events`.
//!
//! Detection modules (`relay`, `tx_velocity`, `canary`) call
//! [`AuditEmitter::emit`] when a rule fires. The emitter:
//!
//! 1. Short-circuits with zero allocation when `enabled = false`.
//! 2. Broadcasts a `LiveEvent` over the WS channel (decoupled from the
//!    rate-limit gate — every detection is visible in real time).
//! 3. Checks a per-`(client_ip, rule_id)` bucket; if currently active the
//!    DB row is suppressed and `rate_limited` ticks.
//! 4. Otherwise enqueues a `CreateSecurityEvent` on a bounded MPSC channel
//!    drained by a supervised worker task.
//! 5. Claims the bucket only AFTER `try_send` returns `Ok` (red-team F1.3 fix)
//!    so a full channel never poisons the IP for a full window.

pub mod broadcast;
pub mod bucket;
pub mod config;
pub mod metrics;
pub mod worker;

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use waf_storage::{Database, models::CreateSecurityEvent};

pub use broadcast::{BroadcastSink, DbBroadcastSink, LiveEvent, NoopBroadcastSink};
pub use bucket::now_epoch_ms;
pub use config::AuditEmitterConfig;
pub use metrics::{AuditEmitterMetrics, AuditEmitterMetricsSnapshot};

use bucket::{BucketStore, make_key};

/// Per-emit caller context. Borrows so the hot path stays alloc-free until
/// rate-limit gate clears.
#[derive(Debug, Clone, Copy)]
pub struct AuditCtx<'a> {
    pub host_code: &'a str,
    pub client_ip: &'a str,
    pub method: &'a str,
    pub path: &'a str,
}

/// Outcome of a single `emit()` invocation. Callers can use it to drive
/// per-detection metric counters or test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Subsystem disabled — no allocation, no DB, no WS broadcast.
    Disabled,
    /// Row queued for DB insert; WS subscribers notified.
    Emitted,
    /// Inside an active window for this `(client_ip, rule_id)` — DB skipped,
    /// WS subscribers still notified.
    RateLimited,
    /// MPSC channel was full; the new event was dropped to protect the
    /// hot path. WS subscribers still notified.
    QueueFullDropped,
}

/// Shared audit emitter — single instance per `WafEngine`.
pub struct AuditEmitter {
    cfg: Arc<ArcSwap<AuditEmitterConfig>>,
    buckets: BucketStore,
    tx: mpsc::Sender<CreateSecurityEvent>,
    sink: Arc<dyn BroadcastSink>,
    metrics: Arc<AuditEmitterMetrics>,
    _worker_handle: JoinHandle<()>,
    _janitor_handle: JoinHandle<()>,
}

impl AuditEmitter {
    /// Build a new emitter and spawn its supervisor + janitor tasks.
    ///
    /// Requires a live Tokio runtime — must be called from inside `#[tokio::main]`
    /// or via a `Handle::block_on` from a runtime context.
    #[must_use]
    pub fn new(db: Arc<Database>, sink: Arc<dyn BroadcastSink>, cfg: AuditEmitterConfig) -> Self {
        let channel_capacity = cfg.channel_capacity;
        let gc_interval_secs = cfg.gc_interval_secs;
        let max_keys = cfg.max_keys;
        let cfg = Arc::new(ArcSwap::from_pointee(cfg));
        let buckets = BucketStore::new();
        let metrics = Arc::new(AuditEmitterMetrics::new());
        let (tx, rx) = mpsc::channel(channel_capacity);

        let worker_handle = worker::spawn_supervisor(db, Arc::clone(&metrics), rx);
        let janitor_handle = worker::spawn_janitor(buckets.clone(), gc_interval_secs, max_keys);

        Self {
            cfg,
            buckets,
            tx,
            sink,
            metrics,
            _worker_handle: worker_handle,
            _janitor_handle: janitor_handle,
        }
    }

    /// Atomically swap in a new config. Hot-reload-safe — operators can
    /// flip `enabled` or tune `window_secs` without restarting the binary.
    ///
    /// Construction-time knobs (`channel_capacity`, `gc_interval_secs`,
    /// `max_keys`) cannot hot-reload because they're bound to live worker
    /// state (MPSC channel depth, janitor ticker, GC cap). If the new
    /// config differs from the running snapshot for any of those three,
    /// we emit a `tracing::warn!` so an operator who edits TOML in
    /// production and expects the change to take effect immediately is
    /// not silently surprised.
    pub fn reload_config(&self, cfg: AuditEmitterConfig) {
        let current = self.cfg.load();
        if current.channel_capacity != cfg.channel_capacity {
            tracing::warn!(
                old = current.channel_capacity,
                new = cfg.channel_capacity,
                "audit_emitter: channel_capacity cannot hot-reload; restart required",
            );
        }
        if current.gc_interval_secs != cfg.gc_interval_secs {
            tracing::warn!(
                old = current.gc_interval_secs,
                new = cfg.gc_interval_secs,
                "audit_emitter: gc_interval_secs cannot hot-reload; restart required",
            );
        }
        if current.max_keys != cfg.max_keys {
            tracing::warn!(
                old = current.max_keys,
                new = cfg.max_keys,
                "audit_emitter: max_keys cannot hot-reload; restart required",
            );
        }
        self.cfg.store(Arc::new(cfg));
    }

    /// Whether the emitter is configured to run. Useful for hot-path callers
    /// that want to skip building an `AuditCtx` when disabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.cfg.load().enabled
    }

    /// Snapshot the current metric counters.
    #[must_use]
    pub fn metrics_snapshot(&self) -> AuditEmitterMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Live live-event sink (test-only accessor; production reads metrics).
    #[cfg(test)]
    #[must_use]
    pub fn sink_arc(&self) -> Arc<dyn BroadcastSink> {
        Arc::clone(&self.sink)
    }

    /// Emit one audit event. Returns the outcome describing whether the
    /// row was queued, suppressed, or dropped.
    ///
    /// Ordering invariants (red-team patched):
    /// 1. WS broadcast fires for EVERY detection — independent of the
    ///    rate-limit gate (F1.5/CC4).
    /// 2. Bucket reservation is atomic via [`BucketStore::try_reserve`] —
    ///    concurrent emits with the same `(client_ip, rule_id)` cannot
    ///    both observe a free slot and both queue rows (C2 race fix).
    /// 3. If `try_send` fails after a successful reservation, the
    ///    reservation is rolled back so the next request can retry.
    pub fn emit(
        &self,
        ctx: &AuditCtx<'_>,
        rule_id: &'static str,
        rule_name: &'static str,
        action: &'static str,
        detail: Option<String>,
    ) -> EmitOutcome {
        let cfg = self.cfg.load();
        if !cfg.enabled {
            return EmitOutcome::Disabled;
        }

        let now_ms = now_epoch_ms();

        // Step 1: WS broadcast OUTSIDE the rate-limit gate (F1.5/CC4 fix).
        // Build the `LiveEvent` lazily — only sinks that actually consume
        // it pay the allocation cost (no-op sinks skip everything).
        self.sink
            .try_broadcast_borrowed(ctx, rule_id, rule_name, action, detail.as_deref(), now_ms);

        // Step 2: atomic check-and-reserve (C2 race fix).
        let window_ms = i64::try_from(cfg.window_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
        let expires_ms = now_ms.saturating_add(window_ms);
        let key = make_key(ctx.client_ip, rule_id);
        if !self.buckets.try_reserve(Arc::clone(&key), now_ms, expires_ms) {
            self.metrics.inc_rate_limited();
            return EmitOutcome::RateLimited;
        }

        // Step 3: build the DB row (after gate — saves allocations on
        // rate-limited path per I4).
        let event = CreateSecurityEvent {
            host_code: ctx.host_code.to_string(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.to_string(),
            path: ctx.path.to_string(),
            rule_id: Some(rule_id.to_string()),
            rule_name: rule_name.to_string(),
            action: action.to_string(),
            detail,
            geo_info: None,
        };

        // Step 4: try_send. Rollback the reservation if the channel cannot
        // accept the row so the next request from this `(ip, rule_id)` can
        // retry instead of being blacked out for a full window (F1.3 fix).
        match self.tx.try_send(event) {
            Ok(()) => {
                self.metrics.inc_emitted();
                EmitOutcome::Emitted
            }
            Err(mpsc::error::TrySendError::Full(_) | mpsc::error::TrySendError::Closed(_)) => {
                self.buckets.rollback(&key, expires_ms);
                self.metrics.inc_queue_full_dropped();
                EmitOutcome::QueueFullDropped
            }
        }
    }

    /// Live bucket count — exposed for tests and operator diagnostics.
    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }
}
