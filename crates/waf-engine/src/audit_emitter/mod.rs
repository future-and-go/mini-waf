/// Shared audit-emission layer bridging detection modules → `security_events`.
///
/// Detection modules (`relay`, `tx_velocity`, future `risk::canary`) call
/// [`AuditEmitter::emit`] when a rule fires. The emitter:
///
/// 1. Short-circuits with zero allocation when `enabled = false`.
/// 2. Validates `rule_id` against the 3-segment grammar `^[A-Z]+-[A-Z]+-\d{3}$`
///    — invalid ids are dropped and `invalid_rule_id` ticks.
/// 3. Broadcasts a `LiveEvent` over the WS channel (decoupled from the
///    rate-limit gate — every detection is visible in real time).
/// 4. Checks the layer-1 per-`(client_ip, rule_id)` bucket; if active the DB
///    row is suppressed and `rate_limited` ticks.
/// 5. Checks the layer-2 global per-`rule_id` token bucket; if exhausted the
///    row is dropped and `global_rate_limited` ticks.
/// 6. Otherwise enqueues a `CreateSecurityEvent` on a bounded MPSC channel
///    drained by a supervised worker task.
/// 7. Rolls back the layer-1 reservation if `try_send` fails so the next
///    request from this key can retry instead of being blacked out for a
///    whole window.
///
/// **Built-in rule_ids only.** The bucket key uses `&'static str` so only
/// const-literal rule_ids may pass through (`BOT-XFF-001`, `BOT-RELAY-001`,
/// `BOT-TOR-001`, `TX-SEQ-001`, `TX-WITHDRAW-001`, `TX-LIMIT-001`, future
/// `HONEYPOT-001`, plus internal `AUDIT-RATELIMIT-001`). Admin-uploaded
/// custom rules go through a different persistence path.
pub mod broadcast;
pub mod bucket;
pub mod config;
pub mod global_bucket;
pub mod metrics;
pub mod sanitize;
pub mod worker;

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::OnceLock;

use arc_swap::ArcSwap;
use regex::Regex;
use tokio::sync::mpsc;
use tracing::warn;
use waf_storage::Database;
use waf_storage::models::CreateSecurityEvent;

pub use broadcast::{BroadcastSink, DbBroadcastSink, NoopBroadcastSink};
pub use bucket::{BucketStore, make_key, now_epoch_ms};
pub use config::{AuditEmitterConfig, CHANNEL_CAPACITY_FLOOR, DEFAULT_GLOBAL_TOKENS_PER_SEC};
pub use global_bucket::{GlobalRateBucket, SharedGlobalBucket, new_shared as new_shared_global_bucket};
pub use metrics::{AuditEmitterMetrics, MetricsSnapshot};
pub use sanitize::{MAX_DETAIL_BYTES, sanitize_detail};

/// Caller context passed by reference so the hot path stays allocation-free
/// until the rate-limit gates clear.
#[derive(Debug, Clone)]
pub struct AuditCtx<'a> {
    pub host_code: &'a str,
    pub client_ip: IpAddr,
    pub method: &'a str,
    pub path: &'a str,
}

/// Result of a single `emit()` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmitOutcome {
    /// Subsystem disabled — no allocation, no DB, no WS broadcast.
    Disabled,
    /// `rule_id` did not match the grammar contract; row dropped.
    InvalidRuleId,
    /// Row queued for DB insert; WS subscribers notified.
    Emitted,
    /// Layer-1 per-key window still active — DB skipped, WS notified.
    RateLimited,
    /// Layer-2 global per-rule-id bucket exhausted — DB skipped, WS notified.
    GlobalRateLimited,
    /// MPSC channel was full; row dropped to protect the hot path.
    QueueFullDropped,
}

/// Compiled regex contract for the 3-segment rule_id grammar.
fn rule_id_regex() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^[A-Z]+-[A-Z]+-\d{3}$").expect("rule_id regex is a valid literal")
    })
}

/// Shared audit emitter — single instance per `WafEngine`.
pub struct AuditEmitter {
    cfg: Arc<ArcSwap<AuditEmitterConfig>>,
    buckets: Arc<BucketStore>,
    global_bucket: SharedGlobalBucket,
    tx: mpsc::Sender<CreateSecurityEvent>,
    sink: Arc<dyn BroadcastSink>,
    metrics: Arc<AuditEmitterMetrics>,
}

impl AuditEmitter {
    /// Build a new emitter and spawn its supervisor + janitor + global-bucket
    /// refill tasks. Requires a live Tokio runtime.
    #[must_use]
    pub fn new(db: Arc<Database>, sink: Arc<dyn BroadcastSink>, cfg: AuditEmitterConfig) -> Arc<Self> {
        let channel_capacity = cfg.resolved_channel_capacity();
        let gc_interval_secs = cfg.gc_interval_secs;
        let max_keys = cfg.max_keys;
        let global_default = cfg.global_tokens_per_sec;
        let global_overrides = cfg.global_rate.overrides.clone();
        let cfg_swap = Arc::new(ArcSwap::from_pointee(cfg));

        let buckets = Arc::new(BucketStore::new());
        let metrics = AuditEmitterMetrics::new();
        let global_bucket = new_shared_global_bucket(global_default, &global_overrides);
        let (tx, rx) = mpsc::channel(channel_capacity);

        worker::spawn_supervisor(rx, db, Arc::clone(&metrics));
        worker::spawn_janitor(Arc::clone(&buckets), gc_interval_secs, max_keys);
        GlobalRateBucket::spawn_refill_task(Arc::clone(&global_bucket), Arc::clone(&metrics));

        Arc::new(Self {
            cfg: cfg_swap,
            buckets,
            global_bucket,
            tx,
            sink,
            metrics,
        })
    }

    /// Hot-reloadable config swap. Construction-time knobs (`channel_capacity`,
    /// `gc_interval_secs`, `max_keys`, `global_tokens_per_sec`,
    /// `global_rate.overrides`) cannot take effect without a restart — drift is
    /// logged so operators are not silently surprised.
    pub fn reload_config(&self, cfg: AuditEmitterConfig) {
        let current = self.cfg.load_full();
        if current.channel_capacity != cfg.channel_capacity {
            warn!(
                target = "audit_emitter",
                old = current.channel_capacity,
                new = cfg.channel_capacity,
                "audit_emitter: channel_capacity cannot hot-reload; restart required"
            );
        }
        if current.gc_interval_secs != cfg.gc_interval_secs {
            warn!(
                target = "audit_emitter",
                old = current.gc_interval_secs,
                new = cfg.gc_interval_secs,
                "audit_emitter: gc_interval_secs cannot hot-reload; restart required"
            );
        }
        if current.max_keys != cfg.max_keys {
            warn!(
                target = "audit_emitter",
                old = current.max_keys,
                new = cfg.max_keys,
                "audit_emitter: max_keys cannot hot-reload; restart required"
            );
        }
        if current.global_tokens_per_sec != cfg.global_tokens_per_sec {
            warn!(
                target = "audit_emitter",
                old = current.global_tokens_per_sec,
                new = cfg.global_tokens_per_sec,
                "audit_emitter: global_tokens_per_sec cannot hot-reload; restart required"
            );
        }
        self.cfg.store(Arc::new(cfg));
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.cfg.load().enabled
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Emit one audit event. Returns the outcome for caller-side observation
    /// (tests, per-detection counters).
    pub fn emit(
        &self,
        ctx: &AuditCtx<'_>,
        rule_id: &'static str,
        rule_name: &'static str,
        action: &'static str,
        detail: Option<String>,
    ) -> EmitOutcome {
        // Single ArcSwap snapshot — downstream reads share one config view.
        let cfg = self.cfg.load_full();
        if !cfg.enabled {
            return EmitOutcome::Disabled;
        }

        // Rule-id grammar gate (BP6). Drop and log invalid ids.
        if !rule_id_regex().is_match(rule_id) {
            self.metrics.inc_invalid_rule_id();
            warn!(
                target = "audit_emitter",
                rule_id, "audit_emitter: invalid rule_id format dropped"
            );
            return EmitOutcome::InvalidRuleId;
        }

        // WS broadcast fires for every passing-grammar detection, regardless
        // of rate-limit gates. The DB sink is the throttled path.
        let live_event = build_live_event(ctx, rule_id, rule_name, action, detail.as_deref());
        let sink = Arc::clone(&self.sink);
        tokio::spawn(async move {
            sink.broadcast(live_event).await;
        });

        // Layer 1 — per-(client_ip, rule_id) window.
        if !self.buckets.try_reserve(ctx.client_ip, rule_id, cfg.window_secs) {
            self.metrics.inc_rate_limited();
            warn!(
                target = "audit_emitter",
                rule_id,
                client_ip = %ctx.client_ip,
                "audit_emitter: per-key rate limit"
            );
            return EmitOutcome::RateLimited;
        }

        // Layer 2 — global per-rule-id token bucket.
        let global_ok = match self.global_bucket.try_lock() {
            Ok(guard) => guard.try_acquire(rule_id),
            Err(_) => {
                // Contention on the global lock is rare; if we cannot acquire
                // immediately, treat as a momentary back-pressure miss rather
                // than blocking the hot path.
                false
            }
        };
        if !global_ok {
            self.buckets.rollback(ctx.client_ip, rule_id, cfg.window_secs);
            self.metrics.inc_global_rate_limited();
            warn!(
                target = "audit_emitter",
                rule_id, "audit_emitter: global rate limit"
            );
            return EmitOutcome::GlobalRateLimited;
        }

        // Build the DB row after both gates clear — saves allocations on the
        // rate-limited paths.
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

        match self.tx.try_send(event) {
            Ok(()) => {
                self.metrics.inc_emitted();
                EmitOutcome::Emitted
            }
            Err(mpsc::error::TrySendError::Full(_)) | Err(mpsc::error::TrySendError::Closed(_)) => {
                self.buckets.rollback(ctx.client_ip, rule_id, cfg.window_secs);
                self.metrics.inc_queue_full_dropped();
                warn!(
                    target = "audit_emitter",
                    rule_id, "audit_emitter: channel full — event dropped"
                );
                EmitOutcome::QueueFullDropped
            }
        }
    }
}

/// Build the JSON payload broadcast to WS subscribers.
fn build_live_event(
    ctx: &AuditCtx<'_>,
    rule_id: &str,
    rule_name: &str,
    action: &str,
    detail: Option<&str>,
) -> serde_json::Value {
    serde_json::json!({
        "kind": "security_event",
        "host_code": ctx.host_code,
        "client_ip": ctx.client_ip.to_string(),
        "method": ctx.method,
        "path": ctx.path,
        "rule_id": rule_id,
        "rule_name": rule_name,
        "action": action,
        "detail": detail,
        "ts_ms": now_epoch_ms(),
    })
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn disabled_cfg() -> AuditEmitterConfig {
        AuditEmitterConfig::default()
    }

    fn enabled_cfg() -> AuditEmitterConfig {
        AuditEmitterConfig {
            enabled: true,
            ..AuditEmitterConfig::default()
        }
    }

    #[test]
    fn rule_id_regex_accepts_three_segment_grammar() {
        assert!(rule_id_regex().is_match("BOT-XFF-001"));
        assert!(rule_id_regex().is_match("BOT-RELAY-001"));
        assert!(rule_id_regex().is_match("BOT-TOR-001"));
        assert!(rule_id_regex().is_match("TX-SEQ-001"));
        assert!(rule_id_regex().is_match("TX-WITHDRAW-001"));
        assert!(rule_id_regex().is_match("TX-LIMIT-001"));
    }

    #[test]
    fn rule_id_regex_rejects_off_grammar() {
        assert!(!rule_id_regex().is_match("BOT-RELAY-TOR-001")); // 4-segment
        assert!(!rule_id_regex().is_match("bot-xff-001")); // lower-case
        assert!(!rule_id_regex().is_match("BOT-XFF-1")); // <3 digits
        assert!(!rule_id_regex().is_match("BOT-XFF-1234")); // >3 digits
        assert!(!rule_id_regex().is_match("BOT_XFF_001")); // wrong sep
        assert!(!rule_id_regex().is_match(""));
    }

    #[test]
    fn ctx_builds_without_alloc_for_borrowed_fields() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ctx = AuditCtx {
            host_code: "site.example",
            client_ip: ip,
            method: "GET",
            path: "/api/x",
        };
        assert_eq!(ctx.host_code, "site.example");
        assert_eq!(ctx.client_ip, ip);
    }

    #[tokio::test]
    async fn disabled_emit_short_circuits() {
        // Build a minimal emitter with a no-op sink and disabled config.
        // We cannot easily mock `Database` without a trait, so we test the
        // hot-path short-circuit via direct ArcSwap inspection.
        let cfg = disabled_cfg();
        let swap = ArcSwap::from_pointee(cfg);
        assert!(!swap.load().enabled);
        // The behavioural assertion below is covered by the integration
        // test `disabled_emit_returns_disabled_without_alloc` in
        // `tests/audit_emitter_unit.rs`.
    }

    #[test]
    fn enabled_cfg_has_enabled_true() {
        assert!(enabled_cfg().enabled);
    }
}
