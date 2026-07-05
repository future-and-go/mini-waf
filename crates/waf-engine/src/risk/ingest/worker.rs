//! Async ingest worker loop.
//!
//! Single tokio task that drains the job queue, maps signals to contributors,
//! and applies them to the risk store. Best-effort: job errors are logged but
//! don't stop the worker.

use std::net::IpAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, warn};

use crate::device_fp::types::FpKey;
use crate::risk::ingest::metrics::IngestMetrics;
use crate::risk::ingest::signal_to_contributor::{SignalWeights, signals_to_contributors};
use crate::risk::key::RiskKey;
use crate::risk::score::clamp_per_request_deltas;
use crate::risk::store::RiskStore;
use crate::time::Clock;

/// Job submitted to the worker queue. Carries at least one actor axis:
/// a fingerprint key (device-fp submissions) or a client IP (request-path
/// submissions that must join the scorer's IP-keyed actor).
#[derive(Debug)]
pub struct Job {
    pub fp_key: Option<FpKey>,
    pub actor_ip: Option<IpAddr>,
    pub signals: Vec<crate::device_fp::signal::Signal>,
    pub submitted_ms: i64,
}

impl Job {
    /// Job keyed by fingerprint (device-fp pipeline).
    #[must_use]
    pub const fn for_fp(fp_key: FpKey, signals: Vec<crate::device_fp::signal::Signal>, submitted_ms: i64) -> Self {
        Self {
            fp_key: Some(fp_key),
            actor_ip: None,
            signals,
            submitted_ms,
        }
    }

    /// Job keyed by client IP (sync request-path submissions).
    #[must_use]
    pub const fn for_ip(ip: IpAddr, signals: Vec<crate::device_fp::signal::Signal>, submitted_ms: i64) -> Self {
        Self {
            fp_key: None,
            actor_ip: Some(ip),
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
    clock: Arc<dyn Clock>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(supervised_worker_loop(rx, store, weights, metrics, clock))
}

async fn supervised_worker_loop(
    mut rx: mpsc::Receiver<Job>,
    store: Arc<dyn RiskStore>,
    weights: SignalWeights,
    metrics: Arc<IngestMetrics>,
    clock: Arc<dyn Clock>,
) {
    // Simple worker loop — errors are handled gracefully per-job, no panic restart needed.
    // Individual job failures are logged but don't kill the worker.
    while let Some(job) = rx.recv().await {
        metrics.dec_queue_depth();

        if let Err(err) = process_job(&job, &store, &weights, &metrics, clock.as_ref()).await {
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
    clock: &dyn Clock,
) -> anyhow::Result<()> {
    let now_ms = clock.now_ms();
    let lag_ms = now_ms.saturating_sub(job.submitted_ms).max(0);

    // Resolve the actor axes the job carries; a job with neither a hashable
    // fingerprint nor an IP cannot be credited to anyone.
    let fp_hash = job.fp_key.as_ref().and_then(RiskKey::hash_fp_key);
    if job.actor_ip.is_none() && fp_hash.is_none() {
        metrics.inc_dropped_key_unresolved();
        debug!(
            target: "risk::ingest",
            "dropping job: no actor axis (empty FpKey, no IP), cannot resolve to RiskKey"
        );
        return Ok(());
    }

    let risk_key = RiskKey {
        ip: job.actor_ip,
        fp_hash,
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

    // One job carries one request's signals — cap its positive delta sum
    // like the sync path does.
    let (contributors, _raw_sum) = clamp_per_request_deltas(&contributors);

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
    use crate::time::SystemClock;
    use crate::time::test_utils::MockClock;

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

        let job = Job::for_fp(
            test_fp_key("test-ja3"),
            vec![Signal::FpConflict { distinct_uas: 3 }],
            SystemClock.now_ms(),
        );

        process_job(&job, &store, &weights, &metrics, &SystemClock)
            .await
            .unwrap();

        // Verify state was updated
        let fp_hash = RiskKey::hash_fp_key(job.fp_key.as_ref().unwrap()).unwrap();
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

        let job = Job::for_fp(
            FpKey::default(), // Empty key — and no IP axis
            vec![Signal::FpConflict { distinct_uas: 3 }],
            SystemClock.now_ms(),
        );

        process_job(&job, &store, &weights, &metrics, &SystemClock)
            .await
            .unwrap();

        assert_eq!(metrics.dropped_key_unresolved(), 1);
        assert_eq!(metrics.processed_total(), 0);
    }

    #[tokio::test]
    async fn ip_keyed_job_applies_to_ip_axis() {
        use std::net::Ipv4Addr;

        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let weights = SignalWeights::default();
        let metrics = Arc::new(IngestMetrics::new());

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7));
        let job = Job::for_ip(ip, vec![Signal::FpConflict { distinct_uas: 3 }], SystemClock.now_ms());

        process_job(&job, &store, &weights, &metrics, &SystemClock)
            .await
            .unwrap();

        // The delta must land on the same IP axis the request-path scorer
        // reads via `RiskKey::from_ip`.
        let state = store.read(&RiskKey::from_ip(ip)).await.unwrap();
        assert!(state.is_some(), "IP-keyed job must be readable at RiskKey::from_ip");
        assert!(state.unwrap().clamped_score > 0);
        assert_eq!(metrics.processed_total(), 1);
    }

    #[tokio::test]
    async fn worker_processes_multiple_jobs() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let weights = SignalWeights::default();
        let metrics = Arc::new(IngestMetrics::new());

        let (tx, rx) = mpsc::channel(16);
        let handle = spawn_worker(
            rx,
            Arc::clone(&store),
            weights,
            Arc::clone(&metrics),
            Arc::new(SystemClock),
        );

        // Send jobs
        for i in 0..5 {
            metrics.inc_queue_depth();
            tx.send(Job::for_fp(
                test_fp_key(&format!("key-{i}")),
                vec![Signal::H2Anomaly {
                    reason: H2AnomalyReason::BadSettings,
                }],
                SystemClock.now_ms(),
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

    #[tokio::test]
    async fn lag_is_deterministic_under_mock_clock() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let weights = SignalWeights::default();
        let metrics = Arc::new(IngestMetrics::new());
        let clock = MockClock::new(1_000_000);

        // Stamp the job at submit time, then advance the shared clock before
        // the worker measures — lag must be exactly the advance, no wall-clock.
        let job = Job::for_fp(
            test_fp_key("lag-key"),
            vec![Signal::FpConflict { distinct_uas: 3 }],
            clock.now_ms(),
        );
        clock.advance_ms(250);

        process_job(&job, &store, &weights, &metrics, &clock).await.unwrap();

        assert_eq!(metrics.processed_total(), 1);
        assert_eq!(metrics.avg_lag_ms(), 250);
    }
}
