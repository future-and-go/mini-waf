use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::broadcast;
use tracing::info;

use crate::StorageError;

/// Database connection wrapper with real-time event broadcast
#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    /// Broadcast channel for real-time security event streaming (WebSocket)
    event_tx: broadcast::Sender<serde_json::Value>,
}

impl Database {
    /// Create a new database connection pool
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        info!("Connecting to PostgreSQL: {}", sanitize_url(database_url));

        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect(database_url)
            .await?;

        let (event_tx, _) = broadcast::channel(1024);

        Ok(Self { pool, event_tx })
    }

    /// Build a `Database` whose pool defers connection until first query.
    ///
    /// Used by downstream tests that need a real `Database` value to thread
    /// through APIs without bringing up `PostgreSQL`. Queries against the
    /// returned pool will fail with a connection error — callers are
    /// expected to either avoid hitting the pool or handle that error.
    pub fn connect_lazy(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(max_connections)
            .connect_lazy(database_url)?;

        let (event_tx, _) = broadcast::channel(1024);

        Ok(Self { pool, event_tx })
    }

    /// Run embedded migrations
    pub async fn migrate(&self) -> Result<(), StorageError> {
        info!("Running database migrations");
        sqlx::migrate!("../../migrations").run(&self.pool).await?;
        info!("Migrations completed");
        Ok(())
    }

    /// Get a reference to the connection pool
    pub const fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Subscribe to real-time security events (for WebSocket streaming)
    pub fn subscribe_events(&self) -> broadcast::Receiver<serde_json::Value> {
        self.event_tx.subscribe()
    }

    /// Broadcast a security event to all WebSocket subscribers.
    ///
    /// Public so engine-side emitters (issue #60 `AuditEmitter`) can push
    /// out-of-band events without going through the DB-backed
    /// `create_security_event` write path.
    pub fn broadcast_event(&self, event: serde_json::Value) {
        let _ = self.event_tx.send(event);
    }

    /// Current WebSocket subscriber count. Used by audit emitters to
    /// short-circuit live-event construction when nobody is listening —
    /// admin dashboards are open for seconds, the WAF runs for months, so
    /// the no-subscriber path is the steady state. Cheap O(1) read.
    #[must_use]
    pub fn event_subscriber_count(&self) -> usize {
        self.event_tx.receiver_count()
    }
}

/// Strip password from URL for logging
fn sanitize_url(url: &str) -> String {
    if let Some(at_pos) = url.rfind('@')
        && let Some(scheme_end) = url.find("://")
    {
        let scheme = &url[..scheme_end + 3];
        let rest = &url[at_pos..];
        return format!("{scheme}***{rest}");
    }
    url.to_string()
}
