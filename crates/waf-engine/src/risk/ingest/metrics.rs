//! FR-025 Phase 4 — Async ingest pipeline metrics.
//!
//! Atomic counters for ingest queue health and processing. Uses `AtomicU64`
//! for lock-free updates. Counters exposed via accessor methods for external
//! metrics exporters (Prometheus, `StatsD`, etc.).

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for risk ingest pipeline events.
///
/// All operations use `Ordering::Relaxed` — sufficient for monotonic counters.
#[derive(Debug, Default)]
pub struct IngestMetrics {
    /// Current queue depth (gauge, can go up/down).
    queue_depth: AtomicU64,
    /// Total signals dropped due to full channel.
    dropped_channel_full: AtomicU64,
    /// Total signals dropped due to unresolved key.
    dropped_key_unresolved: AtomicU64,
    /// Total signals successfully processed.
    processed_total: AtomicU64,
    /// Cumulative lag in milliseconds (for histogram approximation).
    lag_sum_ms: AtomicU64,
    /// Count of lag samples (for computing average).
    lag_samples: AtomicU64,
    /// Worker restart count (panics caught and recovered).
    worker_restarts: AtomicU64,
}

impl IngestMetrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            queue_depth: AtomicU64::new(0),
            dropped_channel_full: AtomicU64::new(0),
            dropped_key_unresolved: AtomicU64::new(0),
            processed_total: AtomicU64::new(0),
            lag_sum_ms: AtomicU64::new(0),
            lag_samples: AtomicU64::new(0),
            worker_restarts: AtomicU64::new(0),
        }
    }

    /// Increment queue depth when a job is enqueued.
    pub fn inc_queue_depth(&self) {
        self.queue_depth.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement queue depth when a job is processed.
    pub fn dec_queue_depth(&self) {
        let _ = self
            .queue_depth
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
    }

    /// Increment dropped counter for channel full reason.
    pub fn inc_dropped_channel_full(&self) {
        self.dropped_channel_full.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment dropped counter for unresolved key reason.
    pub fn inc_dropped_key_unresolved(&self) {
        self.dropped_key_unresolved.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment processed counter and record lag.
    pub fn record_processed(&self, lag_ms: u64) {
        self.processed_total.fetch_add(1, Ordering::Relaxed);
        self.lag_sum_ms.fetch_add(lag_ms, Ordering::Relaxed);
        self.lag_samples.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment worker restart counter.
    pub fn inc_worker_restart(&self) {
        self.worker_restarts.fetch_add(1, Ordering::Relaxed);
    }

    // ─── Accessors for metrics export ─────────────────────────────────────────

    #[must_use]
    pub fn queue_depth(&self) -> u64 {
        self.queue_depth.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_channel_full(&self) -> u64 {
        self.dropped_channel_full.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_key_unresolved(&self) -> u64 {
        self.dropped_key_unresolved.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn dropped_total(&self) -> u64 {
        self.dropped_channel_full() + self.dropped_key_unresolved()
    }

    #[must_use]
    pub fn processed_total(&self) -> u64 {
        self.processed_total.load(Ordering::Relaxed)
    }

    /// Average lag in milliseconds (0 if no samples).
    #[must_use]
    pub fn avg_lag_ms(&self) -> u64 {
        let samples = self.lag_samples.load(Ordering::Relaxed);
        if samples == 0 {
            return 0;
        }
        self.lag_sum_ms.load(Ordering::Relaxed) / samples
    }

    #[must_use]
    pub fn worker_restarts(&self) -> u64 {
        self.worker_restarts.load(Ordering::Relaxed)
    }

    /// Snapshot all metrics for logging/export.
    #[must_use]
    pub fn snapshot(&self) -> IngestMetricsSnapshot {
        IngestMetricsSnapshot {
            queue_depth: self.queue_depth(),
            dropped_channel_full: self.dropped_channel_full(),
            dropped_key_unresolved: self.dropped_key_unresolved(),
            dropped_total: self.dropped_total(),
            processed_total: self.processed_total(),
            avg_lag_ms: self.avg_lag_ms(),
            worker_restarts: self.worker_restarts(),
        }
    }
}

/// Immutable snapshot of ingest metrics for serialization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IngestMetricsSnapshot {
    pub queue_depth: u64,
    pub dropped_channel_full: u64,
    pub dropped_key_unresolved: u64,
    pub dropped_total: u64,
    pub processed_total: u64,
    pub avg_lag_ms: u64,
    pub worker_restarts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_depth_increments_decrements() {
        let m = IngestMetrics::new();
        assert_eq!(m.queue_depth(), 0);

        m.inc_queue_depth();
        m.inc_queue_depth();
        assert_eq!(m.queue_depth(), 2);

        m.dec_queue_depth();
        assert_eq!(m.queue_depth(), 1);

        // Saturating prevents underflow
        m.dec_queue_depth();
        m.dec_queue_depth();
        assert_eq!(m.queue_depth(), 0);
    }

    #[test]
    fn dropped_counters() {
        let m = IngestMetrics::new();

        m.inc_dropped_channel_full();
        m.inc_dropped_channel_full();
        m.inc_dropped_key_unresolved();

        assert_eq!(m.dropped_channel_full(), 2);
        assert_eq!(m.dropped_key_unresolved(), 1);
        assert_eq!(m.dropped_total(), 3);
    }

    #[test]
    fn processed_with_lag() {
        let m = IngestMetrics::new();

        m.record_processed(10);
        m.record_processed(20);
        m.record_processed(30);

        assert_eq!(m.processed_total(), 3);
        assert_eq!(m.avg_lag_ms(), 20); // (10 + 20 + 30) / 3 = 20
    }

    #[test]
    fn avg_lag_zero_when_no_samples() {
        let m = IngestMetrics::new();
        assert_eq!(m.avg_lag_ms(), 0);
    }

    #[test]
    fn worker_restart_counter() {
        let m = IngestMetrics::new();
        m.inc_worker_restart();
        m.inc_worker_restart();
        assert_eq!(m.worker_restarts(), 2);
    }

    #[test]
    fn snapshot_captures_all() {
        let m = IngestMetrics::new();
        m.inc_queue_depth();
        m.inc_dropped_channel_full();
        m.record_processed(50);
        m.inc_worker_restart();

        let snap = m.snapshot();
        assert_eq!(snap.queue_depth, 1);
        assert_eq!(snap.dropped_channel_full, 1);
        assert_eq!(snap.processed_total, 1);
        assert_eq!(snap.avg_lag_ms, 50);
        assert_eq!(snap.worker_restarts, 1);
    }
}
