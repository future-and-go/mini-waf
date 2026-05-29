use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::PgPoolOptions;
use tokio::sync::broadcast;
use tracing::{info, warn};

use crate::StorageError;

/// Maximum number of connection attempts before giving up.
const CONNECT_RETRY_ATTEMPTS: u32 = 3;
/// Initial backoff between connection attempts (doubles each retry).
const CONNECT_RETRY_BASE: Duration = Duration::from_secs(2);
/// Upper bound on backoff duration to prevent excessive waits.
const CONNECT_RETRY_CAP: Duration = Duration::from_secs(30);
/// Timeout for acquiring a connection from the pool (fail-fast on exhaustion).
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
/// Interval between background health-check probes.
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
/// Timeout for a single health-check probe.
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Database connection wrapper with real-time event broadcast
#[derive(Clone)]
pub struct Database {
    pub pool: PgPool,
    /// Broadcast channel for real-time security event streaming (WebSocket)
    event_tx: broadcast::Sender<serde_json::Value>,
}

impl Database {
    /// Create a new database connection pool with retry logic and health monitoring.
    pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
        info!("Connecting to PostgreSQL: {}", sanitize_url(database_url));

        let pool = retry_connect(database_url, max_connections).await?;

        let (event_tx, _) = broadcast::channel(1024);

        // Spawn background health monitor to detect stale/dead connections
        let health_pool = pool.clone();
        tokio::spawn(health_check_loop(health_pool));

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

    /// Broadcast a security event to all WebSocket subscribers
    pub(crate) fn broadcast_event(&self, event: serde_json::Value) {
        let _ = self.event_tx.send(event);
    }
}

/// Attempt to connect to the database with exponential backoff.
///
/// Makes up to `CONNECT_RETRY_ATTEMPTS` attempts. On transient failures
/// (network blip, slow DB startup) retries with doubling backoff capped at
/// `CONNECT_RETRY_CAP`. Returns `StorageError::ConnectionFailed` when all
/// attempts are exhausted.
async fn retry_connect(database_url: &str, max_connections: u32) -> Result<PgPool, StorageError> {
    let mut backoff = CONNECT_RETRY_BASE;

    for attempt in 1..=CONNECT_RETRY_ATTEMPTS {
        info!(
            attempt,
            "PostgreSQL connect attempt {}/{}", attempt, CONNECT_RETRY_ATTEMPTS
        );

        match PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(ACQUIRE_TIMEOUT)
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                info!("PostgreSQL connection established");
                return Ok(pool);
            }
            Err(e) if attempt < CONNECT_RETRY_ATTEMPTS => {
                warn!(
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "Connect failed; retrying in {:?}", backoff,
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(CONNECT_RETRY_CAP);
            }
            Err(e) => {
                return Err(StorageError::ConnectionFailed(format!(
                    "Failed after {CONNECT_RETRY_ATTEMPTS} attempts: {e}",
                )));
            }
        }
    }

    // Safety net: the for loop always returns via Ok or final Err arm above.
    // No unreachable!() — Iron Rules ban panic-capable macros in production.
    Err(StorageError::ConnectionFailed("retry loop exited unexpectedly".into()))
}

/// Background task that probes the pool health at a fixed interval.
///
/// Runs `SELECT 1` every `HEALTH_CHECK_INTERVAL`. On failure or timeout
/// emits a warning for operator alerting. Does not attempt recovery —
/// sqlx reconnects lazily on next acquire.
async fn health_check_loop(pool: PgPool) {
    let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);

    loop {
        interval.tick().await;

        match tokio::time::timeout(HEALTH_CHECK_TIMEOUT, sqlx::query("SELECT 1").execute(&pool)).await {
            Ok(Ok(_)) => { /* healthy */ }
            Ok(Err(e)) => warn!(error = %e, "Pool health check: query failed"),
            Err(_) => warn!("Pool health check: timeout after {:?}", HEALTH_CHECK_TIMEOUT,),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_error_variant_exists_and_displays() {
        let err = StorageError::ConnectionFailed("test failure".into());
        let msg = err.to_string();
        assert!(msg.contains("Connection failed"));
        assert!(msg.contains("test failure"));
    }

    #[test]
    fn sanitize_url_masks_password() {
        let url = "postgres://user:secret@localhost:5432/db";
        let sanitized = sanitize_url(url);
        assert!(!sanitized.contains("secret"));
        assert!(sanitized.contains("***"));
        assert!(sanitized.contains("@localhost:5432/db"));
    }

    #[test]
    fn sanitize_url_passthrough_without_credentials() {
        let url = "postgres://localhost:5432/db";
        let sanitized = sanitize_url(url);
        assert_eq!(sanitized, url);
    }

    #[tokio::test]
    async fn retry_connect_fails_on_invalid_url() {
        let start = std::time::Instant::now();
        let result = retry_connect("postgres://invalid:5432/nonexistent", 1).await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "Expected connection failure");
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("after 3 attempts"),
            "Error should mention retry count, got: {msg}",
        );
        // Backoff: attempt 1 fails immediately, sleep 2s, attempt 2 fails, sleep 4s,
        // attempt 3 fails. Total wait >= 2s (at least first backoff).
        assert!(
            elapsed >= Duration::from_secs(2),
            "Expected backoff delay, elapsed: {elapsed:?}",
        );
    }
}
