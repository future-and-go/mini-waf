//! Atomic counters for audit-emitter observability.
//!
//! Mirrors the lock-free pattern used by `checks::ddos::metrics::DdosMetrics`
//! — `AtomicU64` with `Ordering::Relaxed` (sufficient for monotonic counters
//! consumed by snapshot accessors, not for happens-before).

use std::sync::atomic::{AtomicU64, Ordering};

/// 5 silent-loss modes the emitter must surface to operators:
/// - `emitted` — DB INSERT successfully queued (success path).
/// - `rate_limited` — bucket hit; skipped DB but WS still broadcast.
/// - `queue_full_dropped` — MPSC channel full; new event dropped.
/// - `worker_restarted` — supervisor restarted the panicked worker.
/// - `db_insert_failed` — worker attempted INSERT but it returned an error.
#[derive(Debug, Default)]
pub struct AuditEmitterMetrics {
    emitted: AtomicU64,
    rate_limited: AtomicU64,
    queue_full_dropped: AtomicU64,
    worker_restarted: AtomicU64,
    db_insert_failed: AtomicU64,
}

impl AuditEmitterMetrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            emitted: AtomicU64::new(0),
            rate_limited: AtomicU64::new(0),
            queue_full_dropped: AtomicU64::new(0),
            worker_restarted: AtomicU64::new(0),
            db_insert_failed: AtomicU64::new(0),
        }
    }

    pub fn inc_emitted(&self) {
        self.emitted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_queue_full_dropped(&self) {
        self.queue_full_dropped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_worker_restarted(&self) {
        self.worker_restarted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_db_insert_failed(&self) {
        self.db_insert_failed.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn emitted(&self) -> u64 {
        self.emitted.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rate_limited(&self) -> u64 {
        self.rate_limited.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn queue_full_dropped(&self) -> u64 {
        self.queue_full_dropped.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn worker_restarted(&self) -> u64 {
        self.worker_restarted.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn db_insert_failed(&self) -> u64 {
        self.db_insert_failed.load(Ordering::Relaxed)
    }

    /// Atomic snapshot for telemetry export.
    #[must_use]
    pub fn snapshot(&self) -> AuditEmitterMetricsSnapshot {
        AuditEmitterMetricsSnapshot {
            emitted: self.emitted(),
            rate_limited: self.rate_limited(),
            queue_full_dropped: self.queue_full_dropped(),
            worker_restarted: self.worker_restarted(),
            db_insert_failed: self.db_insert_failed(),
        }
    }
}

/// Point-in-time copy of all counters for export to dashboards / tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEmitterMetricsSnapshot {
    pub emitted: u64,
    pub rate_limited: u64,
    pub queue_full_dropped: u64,
    pub worker_restarted: u64,
    pub db_insert_failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_at_zero() {
        let m = AuditEmitterMetrics::new();
        let snap = m.snapshot();
        assert_eq!(snap.emitted, 0);
        assert_eq!(snap.rate_limited, 0);
        assert_eq!(snap.queue_full_dropped, 0);
        assert_eq!(snap.worker_restarted, 0);
        assert_eq!(snap.db_insert_failed, 0);
    }

    #[test]
    fn each_counter_increments_independently() {
        let m = AuditEmitterMetrics::new();
        m.inc_emitted();
        m.inc_emitted();
        m.inc_rate_limited();
        m.inc_queue_full_dropped();
        m.inc_worker_restarted();
        m.inc_db_insert_failed();
        let snap = m.snapshot();
        assert_eq!(snap.emitted, 2);
        assert_eq!(snap.rate_limited, 1);
        assert_eq!(snap.queue_full_dropped, 1);
        assert_eq!(snap.worker_restarted, 1);
        assert_eq!(snap.db_insert_failed, 1);
    }
}
