//! `ScoringAggregator` implementation.
//!
//! Implements `RiskAggregator` by forwarding signals to a bounded MPSC channel.
//! Fire-and-forget semantics: `submit` never blocks, drops with warning on overflow.

use std::net::IpAddr;
use std::sync::Arc;

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
use crate::time::{Clock, SystemClock};

/// Default channel capacity.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 65536;

/// Async risk aggregator that forwards signals to the ingest worker.
///
/// Bounded channel prevents unbounded memory growth under load. Overflow
/// triggers drop-with-warn (best-effort semantics).
pub struct ScoringAggregator {
    tx: mpsc::Sender<Job>,
    metrics: Arc<IngestMetrics>,
    clock: Arc<dyn Clock>,
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
        Self::start_with_clock(store, weights, capacity, Arc::new(SystemClock))
    }

    /// Start with an injected clock — submit timestamps and worker lag
    /// measurements both read it, so tests can drive time deterministically.
    #[must_use]
    pub fn start_with_clock(
        store: Arc<dyn RiskStore>,
        weights: SignalWeights,
        capacity: usize,
        clock: Arc<dyn Clock>,
    ) -> (Self, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(capacity);
        let metrics = Arc::new(IngestMetrics::new());
        let handle = spawn_worker(rx, store, weights, Arc::clone(&metrics), Arc::clone(&clock));

        (Self { tx, metrics, clock }, handle)
    }

    /// Get a reference to the metrics for external monitoring.
    #[must_use]
    pub const fn metrics(&self) -> &Arc<IngestMetrics> {
        &self.metrics
    }

    /// Enqueue a job without blocking — `try_send` only, drop-with-warn on
    /// overflow. Sync so both submit seams share one code path.
    fn enqueue(&self, job: Job) {
        let signal_count = job.signals.len();

        match self.tx.try_send(job) {
            Ok(()) => {
                self.metrics.inc_queue_depth();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics.inc_dropped_channel_full();
                warn!(
                    target: "risk::ingest",
                    signals = signal_count,
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

#[async_trait]
impl RiskAggregator for ScoringAggregator {
    async fn submit(&self, key: &FpKey, signals: &[Signal]) {
        if signals.is_empty() {
            return;
        }

        self.enqueue(Job::for_fp(key.clone(), signals.to_vec(), self.clock.now_ms()));
    }

    fn submit_ip(&self, ip: IpAddr, signals: &[Signal]) {
        if signals.is_empty() {
            return;
        }

        self.enqueue(Job::for_ip(ip, signals.to_vec(), self.clock.now_ms()));
    }
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
    async fn submit_ip_enqueues_without_blocking() {
        use std::net::Ipv4Addr;

        use crate::risk::key::RiskKey;

        let store: Arc<dyn RiskStore> = Arc::new(MemoryRiskStore::new());
        let (agg, handle) = ScoringAggregator::start(Arc::clone(&store), SignalWeights::default());

        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        // Sync call — no .await, must work from non-async contexts.
        agg.submit_ip(ip, &[Signal::FpConflict { distinct_uas: 3 }]);

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        assert_eq!(agg.metrics().processed_total(), 1);
        let state = store.read(&RiskKey::from_ip(ip)).await.unwrap();
        assert!(state.is_some(), "IP-keyed submission must land on the IP axis");

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
