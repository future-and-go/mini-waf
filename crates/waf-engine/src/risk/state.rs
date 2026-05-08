//! FR-025 risk state types.
//!
//! `RiskState` holds the accumulated risk for a single actor identity.
//! `Contributor` records individual risk events (rule hits, anomalies, signals)
//! in a fixed-size ring buffer for audit.

use serde::{Deserialize, Serialize};
use smallvec::SmallVec;

/// Seed layer classification source (L0 reputation).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SeedKind {
    /// Generic seed (baseline, tests, or unclassified).
    Generic,
    /// IP is a known Tor exit node.
    TorExit,
    /// IP belongs to a datacenter ASN (AWS, GCP, Azure, etc.).
    DatacenterASN,
    /// IP belongs to a known-bad ASN (operator-curated list).
    BadASN,
}

/// Outcome of challenge credit verification (FR-006).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CreditOutcome {
    /// Valid challenge token — grant credit.
    Valid,
    /// Invalid token (bad signature, binding mismatch, malformed).
    Invalid,
    /// Token replay detected — already consumed.
    Replay,
    /// Token expired.
    Expired,
}

/// What kind of event contributed to the risk score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContributorKind {
    /// A WAF rule matched (`rule_id` stored).
    Rule(String),
    /// Behavioral anomaly detected (FR-011).
    Anomaly,
    /// L0 seed layer classification (Tor exit, datacenter ASN, bad ASN).
    Seed(SeedKind),
    /// Named signal from device-fingerprinting or relay intel.
    Signal(String),
    /// Manual override (admin action, honeypot trap).
    Override,
    /// Decay credit applied.
    Decay,
    /// FR-006 challenge credit verification result.
    ChallengeCredit(CreditOutcome),
}

/// A single risk contribution event.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Contributor {
    pub kind: ContributorKind,
    /// Signed delta: positive increases risk, negative credits it.
    pub delta: i16,
    /// Unix timestamp in milliseconds when this event occurred.
    pub ts_ms: i64,
}

impl Contributor {
    #[must_use]
    pub const fn new(kind: ContributorKind, delta: i16, ts_ms: i64) -> Self {
        Self { kind, delta, ts_ms }
    }
}

/// Per-actor risk state.
///
/// Stored in the `RiskStore` and updated atomically on each request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RiskState {
    /// Pre-clamp accumulator — can exceed 0..100 range for audit visibility.
    pub raw_score: i32,
    /// Clamped score used for runtime decisions (0..=100).
    pub clamped_score: u8,
    /// Unix timestamp (ms) of last update.
    pub last_updated_ms: i64,
    /// Unix timestamp (ms) when this state was created.
    pub created_ms: i64,
    /// Most recent contributors (ring buffer, max 8 inline).
    pub contributors: SmallVec<[Contributor; 8]>,
    /// Consecutive "clean" requests (no risk events) — used for decay.
    pub clean_streak: u32,
    /// FR-028 honeypot: floor the score until this timestamp (ms).
    pub pinned_until_ms: Option<i64>,
}

impl Default for RiskState {
    fn default() -> Self {
        Self {
            raw_score: 0,
            clamped_score: 0,
            last_updated_ms: 0,
            created_ms: 0,
            contributors: SmallVec::new(),
            clean_streak: 0,
            pinned_until_ms: None,
        }
    }
}

impl RiskState {
    /// Create a new state initialized at the given timestamp.
    #[must_use]
    pub fn new(now_ms: i64) -> Self {
        Self {
            created_ms: now_ms,
            last_updated_ms: now_ms,
            ..Default::default()
        }
    }

    /// Push a contributor, evicting the oldest if at capacity.
    pub fn push_contributor(&mut self, c: Contributor) {
        const MAX_CONTRIBUTORS: usize = 8;
        if self.contributors.len() >= MAX_CONTRIBUTORS {
            self.contributors.remove(0);
        }
        self.contributors.push(c);
    }

    /// Recalculate `clamped_score` from `raw_score`.
    pub fn reclamp(&mut self) {
        #[allow(clippy::cast_sign_loss)]
        {
            self.clamped_score = self.raw_score.clamp(0, 100) as u8; // safe: clamped to 0..=100
        }
    }

    /// Check if the score is pinned (honeypot floor active).
    #[must_use]
    pub fn is_pinned(&self, now_ms: i64) -> bool {
        self.pinned_until_ms.is_some_and(|until| now_ms < until)
    }

    /// Age in milliseconds since creation.
    #[must_use]
    pub const fn age_ms(&self, now_ms: i64) -> i64 {
        now_ms.saturating_sub(self.created_ms)
    }

    /// Milliseconds since last update.
    #[must_use]
    pub const fn idle_ms(&self, now_ms: i64) -> i64 {
        now_ms.saturating_sub(self.last_updated_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_zero() {
        let s = RiskState::default();
        assert_eq!(s.raw_score, 0);
        assert_eq!(s.clamped_score, 0);
        assert!(s.contributors.is_empty());
    }

    #[test]
    fn push_contributor_evicts_oldest() {
        let mut s = RiskState::new(1000);
        for i in 0..10 {
            s.push_contributor(Contributor::new(
                ContributorKind::Seed(SeedKind::Generic),
                i,
                1000 + i64::from(i),
            ));
        }
        assert_eq!(s.contributors.len(), 8);
        assert_eq!(s.contributors.first().map(|c| c.delta), Some(2));
        assert_eq!(s.contributors.last().map(|c| c.delta), Some(9));
    }

    #[test]
    fn reclamp_bounds_score() {
        let mut s = RiskState {
            raw_score: 150,
            ..Default::default()
        };
        s.reclamp();
        assert_eq!(s.clamped_score, 100);

        s.raw_score = -50;
        s.reclamp();
        assert_eq!(s.clamped_score, 0);
    }

    #[test]
    fn is_pinned_checks_timestamp() {
        let s = RiskState::new(1000);
        assert!(!s.is_pinned(2000));

        let s = RiskState {
            pinned_until_ms: Some(3000),
            ..RiskState::new(1000)
        };
        assert!(s.is_pinned(2000));
        assert!(!s.is_pinned(3000));
        assert!(!s.is_pinned(4000));
    }
}
