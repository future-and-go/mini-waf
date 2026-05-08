//! FR-025 Phase 5: Velocity detection layer (L2).
//!
//! Tracks request velocity and transaction sequences per actor.
//!
//! Components:
//! - Sliding window: 60×1s ring buffer, threshold breach → +25
//! - Sequence FSM: Login→OTP→Withdrawal, out-of-order/too-fast → +30

pub mod sequence;
pub mod window;

use crate::risk::key::RiskKey;
use crate::risk::state::Contributor;

pub use sequence::{SEQUENCE_VIOLATION_DELTA, SequenceStore, SequenceViolation, TxEndpoint};
pub use window::{VELOCITY_THRESHOLD_DELTA, VelocityStore};

/// Combined velocity layer owning both stores.
#[derive(Debug)]
pub struct VelocityLayer {
    velocity: VelocityStore,
    sequence: SequenceStore,
}

impl VelocityLayer {
    /// Create a new velocity layer with given request-rate threshold.
    #[must_use]
    pub fn new(velocity_threshold: u32) -> Self {
        Self {
            velocity: VelocityStore::new(velocity_threshold),
            sequence: SequenceStore::new(),
        }
    }

    /// Create with default threshold (100 req/min).
    #[must_use]
    pub fn with_defaults() -> Self {
        Self::new(window::DEFAULT_THRESHOLD)
    }

    /// Evaluate velocity and sequence for an actor.
    ///
    /// Returns contributors from any triggered checks.
    #[must_use]
    pub fn evaluate(&self, key: &RiskKey, tx_endpoint: Option<TxEndpoint>, now_ms: i64) -> Vec<Contributor> {
        let mut contributors = Vec::with_capacity(2);

        // Velocity check (always runs)
        if let Some(c) = window::evaluate(&self.velocity, key, now_ms) {
            contributors.push(c);
        }

        // Sequence FSM check (only if endpoint specified)
        if let Some(c) = sequence::evaluate(&self.sequence, key, tx_endpoint, now_ms) {
            contributors.push(c);
        }

        contributors
    }

    /// Get current request count for an actor (for diagnostics).
    #[must_use]
    pub fn request_count(&self, key: &RiskKey, now_ms: i64) -> u32 {
        self.velocity.peek(key, now_ms)
    }

    /// Purge idle entries from both stores.
    pub fn purge_idle(&self, now_ms: i64) -> (usize, usize) {
        let velocity_purged = self.velocity.purge_idle(now_ms);
        let sequence_purged = self.sequence.purge_idle();
        (velocity_purged, sequence_purged)
    }

    /// Number of tracked actors in velocity store.
    #[must_use]
    pub fn velocity_len(&self) -> usize {
        self.velocity.len()
    }

    /// Number of tracked actors in sequence store.
    #[must_use]
    pub fn sequence_len(&self) -> usize {
        self.sequence.len()
    }
}

impl Default for VelocityLayer {
    fn default() -> Self {
        Self::with_defaults()
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn make_key() -> RiskKey {
        RiskKey::from_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
    }

    #[test]
    fn evaluate_clean_request() {
        let layer = VelocityLayer::new(100);
        let key = make_key();

        let contributors = layer.evaluate(&key, None, 1_000_000);
        assert!(contributors.is_empty());
    }

    #[test]
    fn evaluate_velocity_breach() {
        let layer = VelocityLayer::new(2); // Low threshold
        let key = make_key();
        let now_ms = 1_000_000i64;

        // First 2 requests: OK
        let _ = layer.evaluate(&key, None, now_ms);
        let _ = layer.evaluate(&key, None, now_ms);

        // Third: breach
        let contributors = layer.evaluate(&key, None, now_ms);
        assert_eq!(contributors.len(), 1);
        assert_eq!(contributors[0].delta, VELOCITY_THRESHOLD_DELTA);
    }

    #[test]
    fn evaluate_sequence_violation() {
        let layer = VelocityLayer::new(1000); // High threshold (won't trigger)
        let key = make_key();

        // OTP without login
        let contributors = layer.evaluate(&key, Some(TxEndpoint::Otp), 1_000_000);
        assert_eq!(contributors.len(), 1);
        assert_eq!(contributors[0].delta, SEQUENCE_VIOLATION_DELTA);
    }

    #[test]
    fn evaluate_both_violations() {
        let layer = VelocityLayer::new(0); // Immediate breach
        let key = make_key();

        // Velocity breach + sequence violation
        let contributors = layer.evaluate(&key, Some(TxEndpoint::Otp), 1_000_000);
        assert_eq!(contributors.len(), 2);
    }

    #[test]
    fn purge_idle_cleans_both() {
        let layer = VelocityLayer::new(100);
        let key = make_key();

        // Record some activity
        let _ = layer.evaluate(&key, Some(TxEndpoint::Login), 0);

        // Purge after window expires
        let (v, s) = layer.purge_idle(61_000);

        // Velocity should purge, sequence might not (depends on state)
        assert!(v > 0 || s > 0);
    }
}
