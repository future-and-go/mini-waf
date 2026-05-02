//! Response-cache statistics counters.
//!
//! `bypassed_critical` is the audit signal for FR-009 AC-1: it MUST tick on
//! every CRITICAL-tier or `NoCache`-policy bypass so operators can prove the
//! tier gate is firing.

use std::sync::atomic::{AtomicU64, Ordering};

use super::policy::BypassReason;

/// Cache statistics counters
#[derive(Debug, Default)]
pub struct CacheStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub stores: AtomicU64,
    /// Count of put/get calls bypassed by tier or `NoCache` policy.
    /// Audit signal for FR-009 AC-1.
    pub bypassed_critical: AtomicU64,
}

impl CacheStats {
    pub fn snapshot(&self) -> CacheStatsSnapshot {
        CacheStatsSnapshot {
            hits: self.hits.load(Ordering::Relaxed),
            misses: self.misses.load(Ordering::Relaxed),
            evictions: self.evictions.load(Ordering::Relaxed),
            stores: self.stores.load(Ordering::Relaxed),
            bypassed_critical: self.bypassed_critical.load(Ordering::Relaxed),
        }
    }

    /// Bump the appropriate bypass counter for a `Verdict::Bypass(reason)`.
    ///
    /// Only `CriticalTier` and `NoCachePolicy` count as "audit" bypasses (they
    /// preserve the Phase-1 `bypassed_critical` semantics). All other reasons
    /// are silent — matching the prior behavior where Set-Cookie / non-2xx /
    /// upstream-Cache-Control bypasses returned `false` without bumping any
    /// counter.
    pub fn record_bypass(&self, reason: BypassReason) {
        if matches!(reason, BypassReason::CriticalTier | BypassReason::NoCachePolicy) {
            self.bypassed_critical.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStatsSnapshot {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub stores: u64,
    pub bypassed_critical: u64,
}
