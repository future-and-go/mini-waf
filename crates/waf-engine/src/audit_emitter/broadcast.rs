/// WS broadcast sink trait and implementations.
///
/// The WS broadcast fires for EVERY detection (not gated by the rate limiter),
/// so admin panel subscribers see live events even when DB writes are throttled.
///
/// Decision (C1 from validate-summary): the existing `Database::broadcast_event`
/// channel already serves `/ws/events` subscribers. Reusing it avoids a second
/// broadcast channel and keeps the WS path thin. The `DbBroadcastSink` calls
/// `db.broadcast_event(json)` directly — no new infrastructure needed.
///
/// `NoopBroadcastSink` is used in unit tests where no DB/WS infra is available.
use std::sync::Arc;

use serde_json::Value as JsonValue;
use waf_storage::Database;

/// Trait for broadcasting a detection event to real-time subscribers.
#[async_trait::async_trait]
pub trait BroadcastSink: Send + Sync + 'static {
    async fn broadcast(&self, event: JsonValue);
}

/// No-op sink for unit tests.
pub struct NoopBroadcastSink;

#[async_trait::async_trait]
impl BroadcastSink for NoopBroadcastSink {
    async fn broadcast(&self, _event: JsonValue) {}
}

/// Production sink that forwards events to the `Database` broadcast channel,
/// which `websocket.rs` subscribes to via `db.subscribe_events()`.
pub struct DbBroadcastSink {
    db: Arc<Database>,
}

impl DbBroadcastSink {
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }
}

#[async_trait::async_trait]
impl BroadcastSink for DbBroadcastSink {
    async fn broadcast(&self, event: JsonValue) {
        self.db.broadcast_event(event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_broadcast_sink_does_not_panic() {
        let sink = NoopBroadcastSink;
        sink.broadcast(serde_json::json!({"rule_id": "BOT-XFF-001"})).await;
    }
}
