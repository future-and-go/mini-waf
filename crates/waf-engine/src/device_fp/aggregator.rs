//! FR-010 risk aggregation trait — the seam where device-fp signals
//! flow out to FR-025 (cumulative risk scorer).
//!
//! ## FR-025 plug-in contract
//!
//! `device_fp/` knows nothing about scoring. It produces [`Signal`]s and
//! hands them to whatever [`RiskAggregator`] was injected at construction.
//! FR-025 ships its own crate, implements this trait, and is wired in by
//! the binary entry point — `device_fp/` never depends on it.
//!
//! ### Semantics
//! - `submit` is async but **MUST NOT block** the caller. Implementations
//!   forward to a bounded channel / queue and drop-with-warn on overflow.
//! - Caller treats `submit` as fire-and-forget — no error path, no result.
//! - `key` is borrowed; clone if the impl needs to retain it.
//!
//! ### Skeleton implementation
//! ```ignore
//! pub struct ScoringAggregator { tx: tokio::sync::mpsc::Sender<Job> }
//!
//! #[async_trait::async_trait]
//! impl RiskAggregator for ScoringAggregator {
//!     async fn submit(&self, key: &FpKey, signals: &[Signal]) {
//!         let job = Job { key: key.clone(), signals: signals.to_vec() };
//!         if self.tx.try_send(job).is_err() {
//!             tracing::warn!("risk-scorer queue full, dropping submission");
//!         }
//!     }
//! }
//! ```

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;

use crate::device_fp::signal::Signal;
use crate::device_fp::types::{FingerprintValue, FpKey};

#[async_trait]
pub trait RiskAggregator: Send + Sync {
    /// Submit a batch of signals tied to one fingerprint key. Implementations
    /// MUST NOT block the caller — fan out to a queue/channel internally.
    async fn submit(&self, key: &FpKey, signals: &[Signal]);
}

/// Default aggregator — discards all submissions. Used when no risk scorer
/// is wired in (e.g. boot order, dev profile, FR-025 disabled).
#[derive(Debug, Default)]
pub struct NoopAggregator;

#[async_trait]
impl RiskAggregator for NoopAggregator {
    async fn submit(&self, key: &FpKey, signals: &[Signal]) {
        // Debug-only — production builds compile this to nothing material
        // when the subscriber's level is above DEBUG.
        tracing::debug!(
            target: "device_fp::aggregator",
            ja3 = ?key.ja3.as_ref().map(FingerprintValue::as_str),
            ja4 = ?key.ja4.as_ref().map(FingerprintValue::as_str),
            h2 = ?key.h2_akamai.as_ref().map(FingerprintValue::as_str),
            count = signals.len(),
            "noop aggregator: submission dropped"
        );
    }
}

/// One recorded submission — `(key, signals)` pair captured by
/// [`LoggingAggregator`] for assertions in integration tests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AggregatorSubmission {
    pub key: FpKey,
    pub signals: Vec<Signal>,
}

/// Test/dev aggregator — records submissions into a bounded ring buffer.
///
/// Newest pushed to back, oldest evicted when full. Cheap clone (`Arc`
/// over a `Mutex<VecDeque>`) so callers can hand the same handle to the
/// detector and to the assertion site. Not for production: submissions
/// are kept in-process for the aggregator's lifetime.
#[derive(Clone, Debug)]
pub struct LoggingAggregator {
    inner: Arc<Mutex<std::collections::VecDeque<AggregatorSubmission>>>,
    cap: usize,
}

impl LoggingAggregator {
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(std::collections::VecDeque::with_capacity(cap.max(1)))),
            cap: cap.max(1),
        }
    }

    /// Snapshot of all retained submissions, oldest first.
    #[must_use]
    pub fn snapshot(&self) -> Vec<AggregatorSubmission> {
        self.inner.lock().iter().cloned().collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

impl Default for LoggingAggregator {
    fn default() -> Self {
        Self::new(64)
    }
}

#[async_trait]
impl RiskAggregator for LoggingAggregator {
    async fn submit(&self, key: &FpKey, signals: &[Signal]) {
        let mut q = self.inner.lock();
        if q.len() == self.cap {
            q.pop_front();
        }
        q.push_back(AggregatorSubmission {
            key: key.clone(),
            signals: signals.to_vec(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::signal::H2AnomalyReason;

    fn empty_key() -> FpKey {
        FpKey {
            ja3: None,
            ja4: None,
            h2_akamai: None,
        }
    }

    #[tokio::test]
    async fn noop_does_not_panic() {
        let agg = NoopAggregator;
        agg.submit(&empty_key(), &[]).await;
    }

    #[tokio::test]
    async fn logging_records_submissions_in_order() {
        let agg = LoggingAggregator::new(8);
        agg.submit(&empty_key(), &[]).await;
        agg.submit(
            &empty_key(),
            &[Signal::H2Anomaly {
                reason: H2AnomalyReason::BadSettings,
            }],
        )
        .await;

        let snap = agg.snapshot();
        assert_eq!(snap.len(), 2);
        assert!(snap.first().unwrap().signals.is_empty());
        assert_eq!(snap.get(1).unwrap().signals.len(), 1);
    }

    #[tokio::test]
    async fn logging_evicts_oldest_when_full() {
        let agg = LoggingAggregator::new(2);
        for _ in 0..3 {
            agg.submit(&empty_key(), &[]).await;
        }
        assert_eq!(agg.len(), 2);
    }
}
