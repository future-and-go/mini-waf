//! FR-010 phase-02 — public Signal enum for device fingerprinting.
//!
//! Flat enum (not trait object) so the risk scorer can match exhaustively
//! and the compiler flags missing branches when new variants land.
//! Mirrors `relay::signal::Signal`.

use serde::{Deserialize, Serialize};

/// Per-detection signal emitted by a [`crate::device_fp::SignalProvider`].
///
/// Variants carry minimal contextual data — the aggregator combines them
/// with provider-configured weights to produce a final risk score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signal {
    /// Same fingerprint observed across multiple distinct UAs in window.
    FpConflict { distinct_uas: u16 },
    /// Same fingerprint observed across `n` distinct IPs in window.
    IpHopping { distinct_ips: u16 },
    /// User-Agent string Shannon entropy below configured threshold.
    LowEntropyUa { entropy_x100: u16 },
    /// User-Agent matched an operator-configured blocklist pattern.
    UaBlocklisted { pattern: String },
    /// HTTP/2 frame sequence deviates from known-good fingerprints.
    H2Anomaly { reason: H2AnomalyReason },
    /// FR-RS-048 — N consecutive inter-request intervals below the burst
    /// threshold (e.g. ≥5 intervals < 50 ms).
    /// `count` is the actual run length observed at fire time.
    BurstInterval { count: u16 },
    /// FR-011 — coefficient of variation across the trailing inter-request
    /// intervals fell below the configured cap, indicating bot-like cadence.
    /// `cv_x1000` is the observed CV scaled ×1000.
    Regularity { cv_x1000: u16 },
    /// FR-RS-049 — actor hammered a single Critical-tier path with no
    /// Referer chain. `samples` is the live sample count at fire time.
    ZeroDepth { samples: u16 },
    /// FR-011 — first request from an unidentified actor on a navigable
    /// path arrived without a Referer header.
    MissingReferer,
}

/// Reason an HTTP/2 anomaly was flagged. Closed enum so risk scorer can
/// exhaustively classify.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum H2AnomalyReason {
    /// SETTINGS frame missing or malformed.
    BadSettings,
    /// Pseudo-header order violates RFC 7540 §8.1.2.1.
    PseudoHeaderOrder,
    /// PRIORITY frame with self-dependency or zero stream id.
    InvalidPriority,
    /// `WINDOW_UPDATE` with zero increment.
    ZeroWindowUpdate,
}

impl Signal {
    /// Stable short name used in logs and metrics labels.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::FpConflict { .. } => "fp_conflict",
            Self::IpHopping { .. } => "ip_hopping",
            Self::LowEntropyUa { .. } => "low_entropy_ua",
            Self::UaBlocklisted { .. } => "ua_blocklisted",
            Self::H2Anomaly { .. } => "h2_anomaly",
            Self::BurstInterval { .. } => "burst_interval",
            Self::Regularity { .. } => "regularity",
            Self::ZeroDepth { .. } => "zero_depth",
            Self::MissingReferer => "missing_referer",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_stable() {
        assert_eq!(Signal::FpConflict { distinct_uas: 2 }.name(), "fp_conflict");
        assert_eq!(Signal::IpHopping { distinct_ips: 5 }.name(), "ip_hopping");
        assert_eq!(Signal::LowEntropyUa { entropy_x100: 100 }.name(), "low_entropy_ua");
        assert_eq!(Signal::UaBlocklisted { pattern: "bot".into() }.name(), "ua_blocklisted");
        assert_eq!(
            Signal::H2Anomaly {
                reason: H2AnomalyReason::BadSettings
            }
            .name(),
            "h2_anomaly"
        );
        assert_eq!(Signal::BurstInterval { count: 5 }.name(), "burst_interval");
        assert_eq!(Signal::Regularity { cv_x1000: 100 }.name(), "regularity");
        assert_eq!(Signal::ZeroDepth { samples: 4 }.name(), "zero_depth");
        assert_eq!(Signal::MissingReferer.name(), "missing_referer");
    }
}
