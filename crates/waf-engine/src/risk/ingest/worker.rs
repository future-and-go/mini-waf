//! FR-025 Phase 4 — Async ingest worker loop.
//!
//! Single tokio task that drains the job queue, maps signals to contributors,
//! and applies them to the risk store. Best-effort: job errors are logged but
//! don't stop the worker.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::device_fp::types::FpKey;
use crate::risk::ingest::metrics::IngestMetrics;
use crate::risk::ingest::signal_to_contributor::{SignalWeights, signals_to_contributors};
use crate::risk::key::RiskKey;
use crate::risk::store::RiskStore;

/// Job submitted to the worker queue.
#[derive(Debug)]
pub struct Job {
    pub fp_key: FpKey,
    pub signals: Vec<crate::device_fp::signal::Signal>,
    pub submitted_ms: i64,
}

impl Job {
    #[must_use]
    pub const fn new(fp_key: FpKey, signals: Vec<crate::device_fp::signal::Signal>, submitted_ms: i64) -> Self {
        Self {
            fp_key,
            signals,
            submitted_ms,
        }
    }
}

/// Spawn the worker loop.
///
/// Returns a `JoinHandle` that can be used to await completion or abort.
/// Errors in individual jobs are logged but don't stop the worker.
pub fn spawn_worker(
    rx: mpsc::Receiver<Job>,
    store: Arc<dyn RiskStore>,
    weights: SignalWeights,
    metrics: Arc<IngestMetrics>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(supervised_worker_loop(rx, store, weights, metrics))
}

async fn supervised_worker_loop(
    mut rx: mpsc::Receiver<Job>,
    store: Arc<dyn RiskStore>,
    weights: SignalWeights,
    metrics: Arc<IngestMetrics>,
) {
    // Simple worker loop — errors are handled gracefully per-job, no panic restart needed.
    // Individual job failures are logged but don't kill the worker.
    while let Some(job) = rx.recv().await {
        metrics.dec_queue_depth();

        if let Err(err) = process_job(&job, &store, &weights, &metrics).await {
            warn!(target: "risk::ingest", ?err, "job processing failed");
        }
    }

    debug!(target: "risk::ingest", "worker channel closed, shutting down");
}

async fn process_job(
    job: &Job,
    store: &Arc<dyn RiskStore>,
    weights: &SignalWeights,
    metrics: &Arc<IngestMetrics>,
) -> anyhow::Result<()> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    let lag_ms = now_ms.saturating_sub(job.submitted_ms).max(0);

    // Build RiskKey from FpKey — using fp_hash only (IP from sync path)
    let Some(fp_hash) = RiskKey::hash_fp_key(&job.fp_key) else {
        // Empty FpKey can't be resolved to a RiskKey
        metrics.inc_dropped_key_unresolved();
        debug!(
            target: "risk::ingest",
            "dropping job: FpKey is empty, cannot resolve to RiskKey"
        );
        return Ok(());
    };

    let risk_key = RiskKey {
        ip: None, // Async path uses fp_hash only; sync path handles IP
        fp_hash: Some(fp_hash),
        session: None,
    };

    // Map signals to contributors
    let contributors = signals_to_contributors(&job.signals, weights, now_ms);

    if contributors.is_empty() {
        // No signals to process (shouldn't happen in practice)
        #[allow(clippy::cast_sign_loss)]
        metrics.record_processed(lag_ms as u64);
        return Ok(());
    }

    // Apply to store
    store.apply(&risk_key, &contributors, now_ms).await?;

    #[allow(clippy::cast_sign_loss)]
    metrics.record_processed(lag_ms as u64);

    debug!(
        target: "risk::ingest",
        signals = job.signals.len(),
        contributors = contributors.len(),
        lag_ms,
        "processed ingest job"
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::signal::{H2AnomalyReason, Signal};
    use crate::device_fp::types::FingerprintValue;
    use crate::risk::store::MemoryRiskStore;

    fn test_fp_key(tag: &str) -> FpKey {
        FpKey {
            ja3: Some(FingerprintValue::new(tag)),
            ja4: None,
            h2_akamai: None,
        }
    }

    #[tokio::test]
    async fn process_job_applies_to_store() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let weights = SignalWeights::default();
        let metrics = Arc::new(IngestMetrics::new());

        let job = Job::new(
            test_fp_key("test-ja3"),
            vec![Signal::FpConflict { distinct_uas: 3 }],
            chrono::Utc::now().timestamp_millis(),
        );

        process_job(&job, &store, &weights, &metrics).await.unwrap();

        // Verify state was updated
        let fp_hash = RiskKey::hash_fp_key(&job.fp_key).unwrap();
        let key = RiskKey {
            ip: None,
            fp_hash: Some(fp_hash),
            session: None,
        };
        let state = store.read(&key).await.unwrap();
        assert!(state.is_some());
        assert!(state.unwrap().clamped_score > 0);
    }

    #[tokio::test]
    async fn empty_fp_key_dropped_with_metric() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let weights = SignalWeights::default();
        let metrics = Arc::new(IngestMetrics::new());

        let job = Job::new(
            FpKey::default(), // Empty key
            vec![Signal::FpConflict { distinct_uas: 3 }],
            chrono::Utc::now().timestamp_millis(),
        );

        process_job(&job, &store, &weights, &metrics).await.unwrap();

        assert_eq!(metrics.dropped_key_unresolved(), 1);
        assert_eq!(metrics.processed_total(), 0);
    }

    #[tokio::test]
    async fn worker_processes_multiple_jobs() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let weights = SignalWeights::default();
        let metrics = Arc::new(IngestMetrics::new());

        let (tx, rx) = mpsc::channel(16);
        let handle = spawn_worker(rx, Arc::clone(&store), weights, Arc::clone(&metrics));

        // Send jobs
        for i in 0..5 {
            metrics.inc_queue_depth();
            tx.send(Job::new(
                test_fp_key(&format!("key-{i}")),
                vec![Signal::H2Anomaly {
                    reason: H2AnomalyReason::BadSettings,
                }],
                chrono::Utc::now().timestamp_millis(),
            ))
            .await
            .unwrap();
        }

        // Close sender to signal worker shutdown
        drop(tx);

        // Wait for worker to finish
        handle.await.unwrap();

        assert_eq!(metrics.processed_total(), 5);
        assert_eq!(metrics.queue_depth(), 0);
    }
}
