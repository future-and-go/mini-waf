/// Atomic counters for the audit emitter subsystem.
///
/// All fields are `AtomicU64` so they can be incremented from any thread
/// without locking. Use `snapshot()` to read a consistent point-in-time view.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Live atomic counters — cheaply `Arc`-shared between emitter and metrics API.
#[derive(Debug, Default)]
pub struct AuditEmitterMetrics {
    /// Total events queued successfully for DB insert.
    pub emitted: AtomicU64,
    /// Events dropped by the per-(ip, rule_id) rate limiter.
    pub rate_limited: AtomicU64,
    /// Events dropped because the bounded channel was full.
    pub queue_full_dropped: AtomicU64,
    /// DB insert failures logged by the supervisor worker.
    pub db_insert_failed: AtomicU64,
    /// Number of times the supervisor worker restarted after a panic.
    pub worker_restarted: AtomicU64,
    /// Events rejected because `rule_id` did not match the grammar contract.
    pub invalid_rule_id: AtomicU64,
    /// Events dropped by the global per-rule-id token-bucket (layer 2).
    pub global_rate_limited: AtomicU64,
}

/// Point-in-time snapshot — all values read with `Relaxed` ordering;
/// counters are monotonic so slight staleness is acceptable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    pub emitted: u64,
    pub rate_limited: u64,
    pub queue_full_dropped: u64,
    pub db_insert_failed: u64,
    pub worker_restarted: u64,
    pub invalid_rule_id: u64,
    pub global_rate_limited: u64,
}

impl AuditEmitterMetrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
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

    pub fn inc_db_insert_failed(&self) {
        self.db_insert_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_worker_restarted(&self) {
        self.worker_restarted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_invalid_rule_id(&self) {
        self.invalid_rule_id.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_global_rate_limited(&self) {
        self.global_rate_limited.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a consistent point-in-time snapshot.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            emitted: self.emitted.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            queue_full_dropped: self.queue_full_dropped.load(Ordering::Relaxed),
            db_insert_failed: self.db_insert_failed.load(Ordering::Relaxed),
            worker_restarted: self.worker_restarted.load(Ordering::Relaxed),
            invalid_rule_id: self.invalid_rule_id.load(Ordering::Relaxed),
            global_rate_limited: self.global_rate_limited.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_counter_atomicity() {
        let m = AuditEmitterMetrics::new();
        m.inc_emitted();
        m.inc_emitted();
        m.inc_rate_limited();
        m.inc_queue_full_dropped();
        m.inc_db_insert_failed();
        m.inc_worker_restarted();
        m.inc_invalid_rule_id();
        m.inc_global_rate_limited();
        let s = m.snapshot();
        assert_eq!(s.emitted, 2);
        assert_eq!(s.rate_limited, 1);
        assert_eq!(s.queue_full_dropped, 1);
        assert_eq!(s.db_insert_failed, 1);
        assert_eq!(s.worker_restarted, 1);
        assert_eq!(s.invalid_rule_id, 1);
        assert_eq!(s.global_rate_limited, 1);
    }

    #[test]
    fn snapshot_independent_of_later_increments() {
        let m = AuditEmitterMetrics::new();
        m.inc_emitted();
        let s1 = m.snapshot();
        m.inc_emitted();
        let s2 = m.snapshot();
        assert_eq!(s1.emitted, 1);
        assert_eq!(s2.emitted, 2);
    }
}
