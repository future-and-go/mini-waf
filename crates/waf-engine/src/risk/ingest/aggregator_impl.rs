//! FR-025 Phase 4 — `ScoringAggregator` implementation.
//!
//! Implements `RiskAggregator` by forwarding signals to a bounded MPSC channel.
//! Fire-and-forget semantics: `submit` never blocks, drops with warning on overflow.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::mpsc;
use tracing::warn;

use crate::device_fp::aggregator::RiskAggregator;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::FpKey;
use crate::risk::ingest::metrics::IngestMetrics;
use crate::risk::ingest::signal_to_contributor::SignalWeights;
use crate::risk::ingest::worker::{Job, spawn_worker};
use crate::risk::store::RiskStore;

/// Default channel capacity (65536 per plan).
pub const DEFAULT_CHANNEL_CAPACITY: usize = 65536;

/// Async risk aggregator that forwards signals to the ingest worker.
///
/// Bounded channel prevents unbounded memory growth under load. Overflow
/// triggers drop-with-warn (best-effort semantics per §3.3 of the plan).
pub struct ScoringAggregator {
    tx: mpsc::Sender<Job>,
    metrics: Arc<IngestMetrics>,
}

impl ScoringAggregator {
    /// Start the aggregator with default channel capacity.
    ///
    /// Returns the aggregator and a `JoinHandle` for the worker task.
    /// The worker runs until the aggregator is dropped (channel closed).
    #[must_use]
    pub fn start(store: Arc<dyn RiskStore>, weights: SignalWeights) -> (Self, tokio::task::JoinHandle<()>) {
        Self::start_with_capacity(store, weights, DEFAULT_CHANNEL_CAPACITY)
    }

    /// Start with custom channel capacity.
    #[must_use]
    pub fn start_with_capacity(
        store: Arc<dyn RiskStore>,
        weights: SignalWeights,
        capacity: usize,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(capacity);
        let metrics = Arc::new(IngestMetrics::new());
        let handle = spawn_worker(rx, store, weights, Arc::clone(&metrics));

        (Self { tx, metrics }, handle)
    }

    /// Get a reference to the metrics for external monitoring.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<IngestMetrics> {
        &self.metrics
    }
}

#[async_trait]
impl RiskAggregator for ScoringAggregator {
    async fn submit(&self, key: &FpKey, signals: &[Signal]) {
        if signals.is_empty() {
            return;
        }

        let now_ms = unix_now_ms();
        let job = Job::new(key.clone(), signals.to_vec(), now_ms);

        // try_send is non-blocking — contract says submit MUST NOT block
        match self.tx.try_send(job) {
            Ok(()) => {
                self.metrics.inc_queue_depth();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.inc_dropped_channel_full();
                warn!(
                    target: "risk::ingest",
                    signals = signals.len(),
                    "queue full, dropping risk signals"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Worker shut down — log but don't count as dropped (intentional shutdown)
                warn!(
                    target: "risk::ingest",
                    "worker channel closed, cannot submit signals"
                );
            }
        }
    }
}

#[allow(clippy::cast_possible_truncation)]
fn unix_now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        // as_millis returns u128; we saturate to i64::MAX (292M years — safe)
        let ms = d.as_millis();
        if ms > i64::MAX as u128 {
            i64::MAX
        } else {
            ms as i64 // safe: guarded by if
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::signal::H2AnomalyReason;
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
    async fn submit_enqueues_job() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let (agg, handle) = ScoringAggregator::start(store, SignalWeights::default());

        agg.submit(
            &test_fp_key("test"),
            &[Signal::H2Anomaly {
                reason: H2AnomalyReason::BadSettings,
            }],
        )
        .await;

        // Give worker time to process
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(agg.metrics().processed_total(), 1);

        drop(agg);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn empty_signals_skipped() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let (agg, handle) = ScoringAggregator::start(store, SignalWeights::default());

        agg.submit(&test_fp_key("test"), &[]).await;

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(agg.metrics().processed_total(), 0);
        assert_eq!(agg.metrics().queue_depth(), 0);

        drop(agg);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn overflow_drops_with_metric() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        // Tiny capacity to force overflow
        let (agg, handle) = ScoringAggregator::start_with_capacity(store, SignalWeights::default(), 2);

        // Submit more than capacity without letting worker drain
        for i in 0..10 {
            agg.submit(
                &test_fp_key(&format!("key-{i}")),
                &[Signal::FpConflict { distinct_uas: 2 }],
            )
            .await;
        }

        // Some should have been dropped
        assert!(agg.metrics().dropped_channel_full() > 0);

        drop(agg);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn graceful_shutdown() {
        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let (agg, handle) = ScoringAggregator::start(store, SignalWeights::default());

        agg.submit(&test_fp_key("test"), &[Signal::Regularity { cv_x1000: 100 }])
            .await;

        // Drop aggregator to close channel
        drop(agg);

        // Worker should exit gracefully
        let result = tokio::time::timeout(tokio::time::Duration::from_secs(1), handle).await;
        assert!(result.is_ok(), "worker should shut down within timeout");
    }
}
