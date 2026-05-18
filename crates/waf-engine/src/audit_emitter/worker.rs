//! Supervised DB-insert worker + janitor task.
//!
//! Red-team F1.4 fix: the worker isolates each DB INSERT inside its own
//! `tokio::spawn`. If a task panics (e.g., serde marshalling bug, runtime
//! corruption), the supervisor logs it, increments the `worker_restarted`
//! counter, sleeps for a short backoff, and resumes draining the queue.
//! A poison-pill row therefore cannot kill the entire worker loop.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::warn;
use waf_storage::{Database, models::CreateSecurityEvent};

use super::bucket::{BucketStore, now_epoch_ms};
use super::metrics::AuditEmitterMetrics;

/// Pause between handling events after a panic, so a deterministic crash
/// doesn't hot-loop the runtime.
const POST_PANIC_BACKOFF: Duration = Duration::from_secs(1);

/// Spawn the supervisor that drains queued events and persists them.
pub fn spawn_supervisor(
    db: Arc<Database>,
    metrics: Arc<AuditEmitterMetrics>,
    rx: mpsc::Receiver<CreateSecurityEvent>,
) -> JoinHandle<()> {
    tokio::spawn(supervise(db, metrics, rx))
}

async fn supervise(db: Arc<Database>, metrics: Arc<AuditEmitterMetrics>, mut rx: mpsc::Receiver<CreateSecurityEvent>) {
    while let Some(event) = rx.recv().await {
        let db_handle = Arc::clone(&db);
        let metrics_handle = Arc::clone(&metrics);
        let insert_task = tokio::spawn(async move { db_handle.create_security_event(event).await });

        match insert_task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                warn!(error = %err, "audit emitter: DB insert failed");
                metrics_handle.inc_db_insert_failed();
            }
            Err(join_err) if join_err.is_panic() => {
                warn!(panic = ?join_err, "audit emitter: DB insert panicked, recovering");
                metrics_handle.inc_worker_restarted();
                tokio::time::sleep(POST_PANIC_BACKOFF).await;
            }
            Err(join_err) => {
                warn!(error = ?join_err, "audit emitter: DB insert task cancelled");
            }
        }
    }
}

/// Spawn the janitor that periodically prunes the bucket store.
pub fn spawn_janitor(buckets: BucketStore, interval_secs: u64, max_keys: usize) -> JoinHandle<()> {
    let interval = Duration::from_secs(interval_secs.max(1));
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip immediate first tick
        loop {
            ticker.tick().await;
            buckets.gc(now_epoch_ms(), max_keys);
            tokio::task::yield_now().await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn janitor_runs_without_panic() {
        let buckets = BucketStore::new();
        let handle = spawn_janitor(buckets, 1, 100);
        tokio::time::sleep(Duration::from_millis(10)).await;
        handle.abort();
    }

    #[test]
    fn post_panic_backoff_is_one_second() {
        assert_eq!(POST_PANIC_BACKOFF, Duration::from_secs(1));
    }
}
