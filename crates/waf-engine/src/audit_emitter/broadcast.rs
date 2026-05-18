//! WebSocket broadcast sink decoupled from the rate-limit gate.
//!
//! Red-team F1.5 / CC4 fix: every detection broadcasts to the in-memory WS
//! channel even when the DB INSERT is suppressed by the per-IP/rule_id
//! window. Subscribers see a complete signal feed; only persistence is
//! windowed.

use std::sync::Arc;

use serde::Serialize;
use waf_storage::Database;

/// One real-time event emitted to WS subscribers.
///
/// Lighter than `CreateSecurityEvent` — carries only the fields a live
/// dashboard cares about. `ts_ms` is wall-clock epoch milliseconds so the
/// UI can render age without re-reading the DB row.
#[derive(Debug, Clone, Serialize)]
pub struct LiveEvent {
    pub host_code: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub rule_id: &'static str,
    pub rule_name: &'static str,
    pub action: &'static str,
    pub detail: Option<String>,
    pub ts_ms: i64,
}

/// Pluggable real-time broadcaster.
///
/// Production impl wires into `Database`'s tokio broadcast channel (consumed
/// by `waf-api/src/websocket.rs`). Test impl records calls in an atomic
/// counter without touching the network.
pub trait BroadcastSink: Send + Sync {
    /// Best-effort broadcast. Must never block the hot path; sink swallows
    /// transient errors (e.g., no subscribers, channel full).
    fn try_broadcast(&self, evt: &LiveEvent);

    /// Borrowed-form broadcast used by the emitter's hot path. Default
    /// implementation falls back to the owned `try_broadcast` so existing
    /// impls keep working; sinks that don't need owned data (no-op,
    /// counting) can override and skip the allocation entirely.
    ///
    /// Issue #60 I4: `emit()` previously allocated a `LiveEvent` with 4
    /// owned `String`s before the rate-limit gate, paying the cost even
    /// for rate-limited calls. This entry point lets non-broadcasting
    /// sinks observe the event without allocation.
    fn try_broadcast_borrowed(
        &self,
        ctx: &super::AuditCtx<'_>,
        rule_id: &'static str,
        rule_name: &'static str,
        action: &'static str,
        detail: Option<&str>,
        ts_ms: i64,
    ) {
        let evt = LiveEvent {
            host_code: ctx.host_code.to_string(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.to_string(),
            path: ctx.path.to_string(),
            rule_id,
            rule_name,
            action,
            detail: detail.map(str::to_owned),
            ts_ms,
        };
        self.try_broadcast(&evt);
    }
}

/// Production sink — forwards into the storage layer's WS broadcast channel.
pub struct DbBroadcastSink {
    db: Arc<Database>,
}

impl DbBroadcastSink {
    #[must_use]
    pub const fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

impl BroadcastSink for DbBroadcastSink {
    fn try_broadcast(&self, evt: &LiveEvent) {
        if let Ok(json) = serde_json::to_value(evt) {
            self.db.broadcast_event(json);
        }
    }

    /// Override the trait default to honor the steady-state where no
    /// admin panel is open: when `receiver_count == 0`, the four `String`
    /// allocations in the default `LiveEvent` construction are pure waste.
    /// Short-circuit before any allocation runs.
    ///
    /// When at least one subscriber is present we fall back to the owned
    /// path — building the JSON value still requires owned `String`s, so
    /// optimising further would mean a custom serializer on borrowed args.
    /// Deferred until a benchmark shows it matters under multi-subscriber
    /// load.
    fn try_broadcast_borrowed(
        &self,
        ctx: &super::AuditCtx<'_>,
        rule_id: &'static str,
        rule_name: &'static str,
        action: &'static str,
        detail: Option<&str>,
        ts_ms: i64,
    ) {
        if self.db.event_subscriber_count() == 0 {
            return;
        }
        let evt = LiveEvent {
            host_code: ctx.host_code.to_string(),
            client_ip: ctx.client_ip.to_string(),
            method: ctx.method.to_string(),
            path: ctx.path.to_string(),
            rule_id,
            rule_name,
            action,
            detail: detail.map(str::to_owned),
            ts_ms,
        };
        self.try_broadcast(&evt);
    }
}

/// No-op sink used by tests that don't care about WS observability.
pub struct NoopBroadcastSink;

impl BroadcastSink for NoopBroadcastSink {
    fn try_broadcast(&self, _evt: &LiveEvent) {}

    fn try_broadcast_borrowed(
        &self,
        _ctx: &super::AuditCtx<'_>,
        _rule_id: &'static str,
        _rule_name: &'static str,
        _action: &'static str,
        _detail: Option<&str>,
        _ts_ms: i64,
    ) {
        // No-op: skip the allocation entirely.
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{BroadcastSink, LiveEvent};

    /// Recording sink used by unit tests — counts broadcasts and stores the
    /// most recent `rule_id` for assertion convenience.
    #[derive(Debug, Default)]
    pub struct CountingSink {
        pub count: AtomicU64,
        pub last_rule_id: parking_lot::Mutex<Option<&'static str>>,
    }

    impl CountingSink {
        #[must_use]
        pub fn arc() -> Arc<Self> {
            Arc::new(Self::default())
        }

        #[must_use]
        pub fn count(&self) -> u64 {
            self.count.load(Ordering::Relaxed)
        }
    }

    impl BroadcastSink for CountingSink {
        fn try_broadcast(&self, evt: &LiveEvent) {
            self.count.fetch_add(1, Ordering::Relaxed);
            *self.last_rule_id.lock() = Some(evt.rule_id);
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use test_support::CountingSink;

    fn sample_event() -> LiveEvent {
        LiveEvent {
            host_code: "demo".into(),
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/".into(),
            rule_id: "TEST-001",
            rule_name: "test_rule",
            action: "log_only",
            detail: None,
            ts_ms: 0,
        }
    }

    #[test]
    fn noop_sink_swallows_event() {
        let sink = NoopBroadcastSink;
        sink.try_broadcast(&sample_event());
    }

    #[test]
    fn counting_sink_records_calls() {
        let sink = CountingSink::arc();
        let evt = sample_event();
        sink.try_broadcast(&evt);
        sink.try_broadcast(&evt);
        assert_eq!(sink.count(), 2);
        assert_eq!(*sink.last_rule_id.lock(), Some("TEST-001"));
    }

    #[test]
    fn live_event_serializes_to_json() {
        let json = serde_json::to_value(sample_event()).expect("serialize");
        assert_eq!(json["rule_id"], "TEST-001");
        assert_eq!(json["action"], "log_only");
    }
}
