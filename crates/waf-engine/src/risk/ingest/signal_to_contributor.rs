//! Signal → Contributor mapping for async ingest pipeline.
//!
//! Pure function that converts device-fingerprinting signals into risk
//! contributors. Weights are configurable via `SignalWeights`.

use std::collections::HashMap;

use tracing::warn;

use crate::device_fp::signal::{H2AnomalyReason, Signal};
use crate::risk::state::{Contributor, ContributorKind};

/// Configurable weights for signal → delta mapping.
///
/// Default values match the plan table. Operators can override via
/// `risk.signal_weights` in the config YAML.
#[derive(Clone, Debug)]
pub struct SignalWeights {
    weights: HashMap<&'static str, i16>,
}

impl Default for SignalWeights {
    fn default() -> Self {
        let mut weights = HashMap::new();
        weights.insert("fp_conflict", 20);
        weights.insert("fp_conflict_high", 30); // uas >= 4
        weights.insert("ip_hopping", 15);
        weights.insert("ip_hopping_high", 25); // ips >= 5
        weights.insert("low_entropy_ua", 10);
        weights.insert("ua_blocklisted", 25);
        weights.insert("h2_anomaly_bad_settings", 15);
        weights.insert("h2_anomaly_pseudo_header", 15);
        weights.insert("h2_anomaly_other", 10);
        weights.insert("burst_interval", 20);
        weights.insert("burst_interval_high", 30); // count >= 10
        weights.insert("regularity", 25);
        weights.insert("zero_depth", 20);
        weights.insert("missing_referer", 5);
        weights.insert("tx_sequence_too_fast", 25);
        weights.insert("withdrawal_velocity", 30);
        weights.insert("limit_change_burst", 25);
        Self { weights }
    }
}

impl SignalWeights {
    /// Create from a user-provided map. Unknown keys are logged and ignored.
    #[must_use]
    pub fn from_overrides(overrides: &HashMap<String, i16>) -> Self {
        let mut sw = Self::default();
        for (key, &val) in overrides {
            if let Some(slot) = sw.weights.get_mut(key.as_str()) {
                *slot = val;
            } else {
                warn!(
                    target: "risk::ingest",
                    key,
                    "unknown signal weight override, ignoring"
                );
            }
        }
        sw
    }

    fn get(&self, key: &str) -> i16 {
        self.weights.get(key).copied().unwrap_or(10)
    }
}

/// Map a single signal to a contributor.
///
/// Returns the contributor with the appropriate delta based on signal
/// severity and configured weights.
#[must_use]
pub fn signal_to_contributor(signal: &Signal, weights: &SignalWeights, ts_ms: i64) -> Contributor {
    let (kind, delta) = match signal {
        Signal::FpConflict { distinct_uas } => {
            let delta = if *distinct_uas >= 4 {
                weights.get("fp_conflict_high")
            } else {
                weights.get("fp_conflict")
            };
            (ContributorKind::Signal("fp_conflict".into()), delta)
        }

        Signal::IpHopping { distinct_ips } => {
            let delta = if *distinct_ips >= 5 {
                weights.get("ip_hopping_high")
            } else {
                weights.get("ip_hopping")
            };
            (ContributorKind::Signal("ip_hopping".into()), delta)
        }

        Signal::LowEntropyUa { .. } => (
            ContributorKind::Signal("low_entropy_ua".into()),
            weights.get("low_entropy_ua"),
        ),

        Signal::UaBlocklisted { .. } => (
            ContributorKind::Signal("ua_blocklisted".into()),
            weights.get("ua_blocklisted"),
        ),

        Signal::H2Anomaly { reason } => {
            let delta = match reason {
                H2AnomalyReason::BadSettings | H2AnomalyReason::PseudoHeaderOrder => {
                    if matches!(reason, H2AnomalyReason::BadSettings) {
                        weights.get("h2_anomaly_bad_settings")
                    } else {
                        weights.get("h2_anomaly_pseudo_header")
                    }
                }
                H2AnomalyReason::InvalidPriority | H2AnomalyReason::ZeroWindowUpdate => weights.get("h2_anomaly_other"),
            };
            (ContributorKind::Signal("h2_anomaly".into()), delta)
        }

        Signal::BurstInterval { count } => {
            let delta = if *count >= 10 {
                weights.get("burst_interval_high")
            } else {
                weights.get("burst_interval")
            };
            (ContributorKind::Signal("burst_interval".into()), delta)
        }

        Signal::Regularity { .. } => (ContributorKind::Signal("regularity".into()), weights.get("regularity")),

        Signal::ZeroDepth { .. } => (ContributorKind::Signal("zero_depth".into()), weights.get("zero_depth")),

        Signal::MissingReferer => (
            ContributorKind::Signal("missing_referer".into()),
            weights.get("missing_referer"),
        ),

        Signal::TxSequenceTooFast { .. } => (
            ContributorKind::Signal("tx_sequence_too_fast".into()),
            weights.get("tx_sequence_too_fast"),
        ),

        Signal::WithdrawalVelocity { .. } => (
            ContributorKind::Signal("withdrawal_velocity".into()),
            weights.get("withdrawal_velocity"),
        ),

        Signal::LimitChangeBurst { .. } => (
            ContributorKind::Signal("limit_change_burst".into()),
            weights.get("limit_change_burst"),
        ),
    };

    Contributor::new(kind, delta, ts_ms)
}

/// Map multiple signals to contributors.
#[must_use]
pub fn signals_to_contributors(signals: &[Signal], weights: &SignalWeights, ts_ms: i64) -> Vec<Contributor> {
    signals
        .iter()
        .map(|s| signal_to_contributor(s, weights, ts_ms))
        .collect()
}

#[cfg(test)]
#[allow(clippy::uninlined_format_args)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::EndpointRole;

    #[test]
    fn all_signal_variants_mapped() {
        let weights = SignalWeights::default();
        let ts = 1000;

        let signals = [
            Signal::FpConflict { distinct_uas: 2 },
            Signal::IpHopping { distinct_ips: 3 },
            Signal::LowEntropyUa { entropy_x100: 100 },
            Signal::UaBlocklisted { pattern: "bot".into() },
            Signal::H2Anomaly {
                reason: H2AnomalyReason::BadSettings,
            },
            Signal::BurstInterval { count: 5 },
            Signal::Regularity { cv_x1000: 100 },
            Signal::ZeroDepth { samples: 4 },
            Signal::MissingReferer,
            Signal::TxSequenceTooFast {
                from: EndpointRole::Login,
                to: EndpointRole::Otp,
                interval_ms: 500,
            },
            Signal::WithdrawalVelocity {
                count: 5,
                ok_count: 5,
                window_sec: 60,
            },
            Signal::LimitChangeBurst {
                count: 3,
                ok_count: 3,
                window_sec: 60,
            },
        ];

        for signal in &signals {
            let contrib = signal_to_contributor(signal, &weights, ts);
            assert!(contrib.delta > 0, "signal {:?} should have positive delta", signal);
        }
    }

    #[test]
    fn fp_conflict_high_threshold() {
        let weights = SignalWeights::default();
        let low = signal_to_contributor(&Signal::FpConflict { distinct_uas: 3 }, &weights, 0);
        let high = signal_to_contributor(&Signal::FpConflict { distinct_uas: 4 }, &weights, 0);
        assert_eq!(low.delta, 20);
        assert_eq!(high.delta, 30);
    }

    #[test]
    fn ip_hopping_high_threshold() {
        let weights = SignalWeights::default();
        let low = signal_to_contributor(&Signal::IpHopping { distinct_ips: 4 }, &weights, 0);
        let high = signal_to_contributor(&Signal::IpHopping { distinct_ips: 5 }, &weights, 0);
        assert_eq!(low.delta, 15);
        assert_eq!(high.delta, 25);
    }

    #[test]
    fn burst_interval_high_threshold() {
        let weights = SignalWeights::default();
        let low = signal_to_contributor(&Signal::BurstInterval { count: 9 }, &weights, 0);
        let high = signal_to_contributor(&Signal::BurstInterval { count: 10 }, &weights, 0);
        assert_eq!(low.delta, 20);
        assert_eq!(high.delta, 30);
    }

    #[test]
    fn custom_weights_override() {
        let mut overrides = HashMap::new();
        overrides.insert("fp_conflict".to_string(), 50);
        let weights = SignalWeights::from_overrides(&overrides);

        let contrib = signal_to_contributor(&Signal::FpConflict { distinct_uas: 2 }, &weights, 0);
        assert_eq!(contrib.delta, 50);
    }

    #[test]
    fn h2_anomaly_severity() {
        let weights = SignalWeights::default();
        let bad_settings = signal_to_contributor(
            &Signal::H2Anomaly {
                reason: H2AnomalyReason::BadSettings,
            },
            &weights,
            0,
        );
        let other = signal_to_contributor(
            &Signal::H2Anomaly {
                reason: H2AnomalyReason::ZeroWindowUpdate,
            },
            &weights,
            0,
        );
        assert_eq!(bad_settings.delta, 15);
        assert_eq!(other.delta, 10);
    }
}
