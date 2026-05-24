//! Rule engine observability metrics — atomic counters for rule load/fire events.

use std::sync::atomic::{AtomicU64, Ordering};

/// Atomic counters for rule engine observability.
#[derive(Debug, Default)]
pub struct RuleMetrics {
    /// Rules loaded successfully (total across all loads).
    rules_loaded_ok: AtomicU64,
    /// Rules that failed to load.
    rules_loaded_fail: AtomicU64,
    /// Total rule fire events.
    rule_fires: AtomicU64,
    /// Data file reload events (cache misses in `DataFileRegistry`).
    data_file_reloads: AtomicU64,
}

impl RuleMetrics {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            rules_loaded_ok: AtomicU64::new(0),
            rules_loaded_fail: AtomicU64::new(0),
            rule_fires: AtomicU64::new(0),
            data_file_reloads: AtomicU64::new(0),
        }
    }

    pub fn inc_loaded_ok(&self, count: u64) {
        self.rules_loaded_ok.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_loaded_fail(&self, count: u64) {
        self.rules_loaded_fail.fetch_add(count, Ordering::Relaxed);
    }

    pub fn inc_rule_fire(&self) {
        self.rule_fires.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_data_file_reloads(&self, count: u64) {
        self.data_file_reloads.fetch_add(count, Ordering::Relaxed);
    }

    #[must_use]
    pub fn rules_loaded_ok(&self) -> u64 {
        self.rules_loaded_ok.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rules_loaded_fail(&self) -> u64 {
        self.rules_loaded_fail.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn rule_fires(&self) -> u64 {
        self.rule_fires.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn data_file_reloads(&self) -> u64 {
        self.data_file_reloads.load(Ordering::Relaxed)
    }

    #[must_use]
    pub fn snapshot(&self) -> RuleMetricsSnapshot {
        RuleMetricsSnapshot {
            rules_loaded_ok: self.rules_loaded_ok(),
            rules_loaded_fail: self.rules_loaded_fail(),
            rule_fires: self.rule_fires(),
            data_file_reloads: self.data_file_reloads(),
        }
    }
}

/// Immutable snapshot for serialization / export.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleMetricsSnapshot {
    pub rules_loaded_ok: u64,
    pub rules_loaded_fail: u64,
    pub rule_fires: u64,
    pub data_file_reloads: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_and_snapshot() {
        let m = RuleMetrics::new();
        m.inc_loaded_ok(5);
        m.inc_loaded_fail(2);
        m.inc_rule_fire();
        m.inc_rule_fire();
        m.inc_data_file_reloads(3);

        let snap = m.snapshot();
        assert_eq!(snap.rules_loaded_ok, 5);
        assert_eq!(snap.rules_loaded_fail, 2);
        assert_eq!(snap.rule_fires, 2);
        assert_eq!(snap.data_file_reloads, 3);
    }

    #[test]
    fn default_is_zero() {
        let m = RuleMetrics::new();
        assert_eq!(m.rules_loaded_ok(), 0);
        assert_eq!(m.rules_loaded_fail(), 0);
        assert_eq!(m.rule_fires(), 0);
        assert_eq!(m.data_file_reloads(), 0);
    }
}
