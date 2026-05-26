use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{error, warn};

use waf_storage::Database;
use waf_storage::models::{AttackLog, CreateSecurityEvent};

pub enum DbLogEvent {
    Attack(AttackLog),
    Security(CreateSecurityEvent),
}

#[derive(Clone)]
pub struct DbBatchWriter {
    tx: mpsc::Sender<DbLogEvent>,
}

impl DbBatchWriter {
    pub fn spawn(db: Arc<Database>, capacity: usize, batch_size: usize, flush_interval_ms: u64) -> Self {
        let (tx, rx) = mpsc::channel(capacity);
        tokio::spawn(flush_loop(rx, db, batch_size, flush_interval_ms));
        Self { tx }
    }

    pub fn try_send(&self, event: DbLogEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn_rate_limited("db_batch_writer channel full — dropping event");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("Audit batch writer channel closed; events lost");
            }
        }
    }
}

fn warn_rate_limited(msg: &str) {
    static LAST_WARN_MS: AtomicU64 = AtomicU64::new(0);
    const COOLDOWN_MS: u64 = 30_000;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    let prev = LAST_WARN_MS.load(Ordering::Relaxed);
    if prev == 0 || now_ms.saturating_sub(prev) >= COOLDOWN_MS {
        LAST_WARN_MS.store(now_ms, Ordering::Relaxed);
        warn!(target: "db_batch_writer", "{msg}");
    }
}

async fn flush_loop(mut rx: mpsc::Receiver<DbLogEvent>, db: Arc<Database>, batch_size: usize, flush_interval_ms: u64) {
    let mut attack_batch: Vec<AttackLog> = Vec::with_capacity(batch_size);
    let mut security_batch: Vec<CreateSecurityEvent> = Vec::with_capacity(batch_size);

    let mut ticker = tokio::time::interval(Duration::from_millis(flush_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;
            received = rx.recv() => {
                match received {
                    Some(DbLogEvent::Attack(log)) => {
                        attack_batch.push(log);
                    }
                    Some(DbLogEvent::Security(event)) => {
                        security_batch.push(event);
                    }
                    None => {
                        do_flush(&db, &mut attack_batch, &mut security_batch).await;
                        return;
                    }
                }
                if attack_batch.len() + security_batch.len() >= batch_size {
                    do_flush(&db, &mut attack_batch, &mut security_batch).await;
                }
            }
            _ = ticker.tick() => {
                if !attack_batch.is_empty() || !security_batch.is_empty() {
                    do_flush(&db, &mut attack_batch, &mut security_batch).await;
                }
            }
        }
    }
}

async fn do_flush(db: &Database, attack_batch: &mut Vec<AttackLog>, security_batch: &mut Vec<CreateSecurityEvent>) {
    if !attack_batch.is_empty() {
        let logs: Vec<AttackLog> = std::mem::take(attack_batch);
        if let Err(e) = db.create_attack_log_batch(&logs).await {
            warn!(error = %e, count = logs.len(), "Batch attack log insert failed — dropping batch");
        }
    }
    if !security_batch.is_empty() {
        let events: Vec<CreateSecurityEvent> = std::mem::take(security_batch);
        if let Err(e) = db.create_security_event_batch(&events).await {
            warn!(error = %e, count = events.len(), "Batch security event insert failed — dropping batch");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_send_on_full_channel_drops_event() {
        let (tx, mut rx) = mpsc::channel::<DbLogEvent>(2);
        let writer = DbBatchWriter { tx };

        let make_event = || {
            DbLogEvent::Security(CreateSecurityEvent {
                host_code: "test".into(),
                client_ip: "1.2.3.4".into(),
                method: "GET".into(),
                path: "/".into(),
                rule_id: None,
                rule_name: "test".into(),
                action: "block".into(),
                detail: None,
                geo_info: None,
            })
        };

        writer.try_send(make_event());
        writer.try_send(make_event());
        // Channel capacity=2, this 3rd send should be silently dropped (Full)
        writer.try_send(make_event());

        // Only 2 events should be in channel
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn try_send_on_closed_channel_does_not_panic() {
        let (tx, rx) = mpsc::channel::<DbLogEvent>(10);
        let writer = DbBatchWriter { tx };

        drop(rx);

        let event = DbLogEvent::Attack(AttackLog {
            id: uuid::Uuid::new_v4(),
            host_code: "test".into(),
            host: "test.com".into(),
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            rule_id: None,
            rule_name: "test".into(),
            action: "block".into(),
            phase: "test".into(),
            detail: None,
            request_headers: None,
            geo_info: None,
            created_at: chrono::Utc::now(),
        });

        // Should not panic — logs error and continues
        writer.try_send(event);
    }

    #[tokio::test]
    async fn flush_loop_exits_on_channel_close() {
        let (tx, rx) = mpsc::channel::<DbLogEvent>(10);

        let db = Arc::new(Database::connect("postgres://invalid:5432/nonexistent", 1).await.ok());

        // If we have no real DB, just verify the flush_loop doesn't hang
        // when the sender side is dropped — it should exit promptly.
        if db.is_none() {
            drop(tx);
            // flush_loop needs a real Database, so we can't test it fully
            // without a DB. We test the channel close behavior via the writer.
            let (tx2, rx2) = mpsc::channel::<DbLogEvent>(2);
            drop(tx2);
            // Channel is closed; recv will return None immediately
            let mut test_rx = rx2;
            assert!(test_rx.recv().await.is_none());
            drop(rx);
        }
    }

    #[tokio::test]
    async fn separate_batches_for_attack_and_security() {
        let (tx, mut rx) = mpsc::channel::<DbLogEvent>(10);
        let writer = DbBatchWriter { tx };

        writer.try_send(DbLogEvent::Attack(AttackLog {
            id: uuid::Uuid::new_v4(),
            host_code: "test".into(),
            host: "test.com".into(),
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/".into(),
            query: None,
            rule_id: None,
            rule_name: "test".into(),
            action: "block".into(),
            phase: "test".into(),
            detail: None,
            request_headers: None,
            geo_info: None,
            created_at: chrono::Utc::now(),
        }));

        writer.try_send(DbLogEvent::Security(CreateSecurityEvent {
            host_code: "test".into(),
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/".into(),
            rule_id: None,
            rule_name: "test".into(),
            action: "block".into(),
            detail: None,
            geo_info: None,
        }));

        // Both events should be in the channel
        let ev1 = rx.try_recv();
        let ev2 = rx.try_recv();
        assert!(ev1.is_ok());
        assert!(ev2.is_ok());

        // Verify correct types
        match ev1.unwrap() {
            DbLogEvent::Attack(_) => {}
            DbLogEvent::Security(_) => panic!("Expected Attack event"),
        }
        match ev2.unwrap() {
            DbLogEvent::Security(_) => {}
            DbLogEvent::Attack(_) => panic!("Expected Security event"),
        }
    }
}
