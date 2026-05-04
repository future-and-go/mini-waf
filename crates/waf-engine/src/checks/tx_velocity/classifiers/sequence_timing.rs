//! Login → OTP → Deposit transition timing classifier.
//!
//! Fires when the most recent event is the "to" role of a tracked transition
//! (Login→Otp or Otp→Deposit) and the prior event of the matching "from"
//! role landed less than `min_human_ms` earlier. Older history is ignored
//! so a slow sequence followed by a fast retry still fires correctly.

use crate::checks::tx_velocity::EndpointRole;
use crate::checks::tx_velocity::classifier::Classifier;
use crate::checks::tx_velocity::config::TxVelocityConfig;
use crate::checks::tx_velocity::recorder::ActorTxSnapshot;
use crate::device_fp::signal::Signal;

pub struct SequenceTimingClassifier;

/// Tracked transitions. Order matters for matching the "to" role.
const TRANSITIONS: &[(EndpointRole, EndpointRole)] = &[
    (EndpointRole::Login, EndpointRole::Otp),
    (EndpointRole::Otp, EndpointRole::Deposit),
];

impl Classifier for SequenceTimingClassifier {
    fn name(&self) -> &'static str {
        "tx_sequence_timing"
    }

    fn evaluate(&self, snap: &ActorTxSnapshot, _now_ms: u64, cfg: &TxVelocityConfig) -> Option<Signal> {
        let scfg = cfg.classifiers.sequence.as_ref()?;
        // Snapshot is oldest → newest; inspect the latest event.
        let last = snap.events.last()?;
        let (from, to) = TRANSITIONS.iter().copied().find(|(_, to)| *to == last.role)?;

        // Find the most-recent prior event with `from` role. Walk backwards
        // skipping the final element (which is `to`).
        let prior = snap.events.iter().rev().skip(1).find(|e| e.role == from)?;

        let interval_ms = last.ts_ms.saturating_sub(prior.ts_ms);
        if interval_ms < scfg.min_human_ms {
            Some(Signal::TxSequenceTooFast { from, to, interval_ms })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::Event;
    use crate::checks::tx_velocity::config::SequenceCfg;

    fn cfg_with(min_human_ms: u64) -> TxVelocityConfig {
        TxVelocityConfig {
            classifiers: crate::checks::tx_velocity::config::ClassifierConfigs {
                sequence: Some(SequenceCfg { min_human_ms }),
                ..crate::checks::tx_velocity::config::ClassifierConfigs::default()
            },
            ..TxVelocityConfig::default()
        }
    }

    fn snap(events: Vec<Event>) -> ActorTxSnapshot {
        let updated_ms = events.last().map_or(0, |e| e.ts_ms);
        ActorTxSnapshot {
            events,
            updated_ms,
            last_signal_ms: 0,
        }
    }

    fn ev(role: EndpointRole, ts_ms: u64) -> Event {
        Event { role, ts_ms, ok: true }
    }

    #[test]
    fn fires_on_fast_login_to_otp() {
        let s = snap(vec![ev(EndpointRole::Login, 100), ev(EndpointRole::Otp, 600)]);
        let out = SequenceTimingClassifier.evaluate(&s, 600, &cfg_with(1500));
        assert!(matches!(
            out,
            Some(Signal::TxSequenceTooFast {
                from: EndpointRole::Login,
                to: EndpointRole::Otp,
                interval_ms: 500,
            })
        ));
    }

    #[test]
    fn does_not_fire_when_interval_meets_threshold() {
        let s = snap(vec![ev(EndpointRole::Login, 0), ev(EndpointRole::Otp, 2_000)]);
        let out = SequenceTimingClassifier.evaluate(&s, 2_000, &cfg_with(1500));
        assert!(out.is_none());
    }

    #[test]
    fn fires_on_otp_to_deposit_using_most_recent_otp() {
        // Slow first OTP, then a fast retry → Deposit. Should still fire on
        // the latest OTP, not the older one.
        let s = snap(vec![
            ev(EndpointRole::Otp, 0),
            ev(EndpointRole::Otp, 9_000),
            ev(EndpointRole::Deposit, 9_400),
        ]);
        let out = SequenceTimingClassifier.evaluate(&s, 9_400, &cfg_with(1500));
        assert!(matches!(
            out,
            Some(Signal::TxSequenceTooFast {
                from: EndpointRole::Otp,
                to: EndpointRole::Deposit,
                interval_ms: 400,
            })
        ));
    }

    #[test]
    fn ignored_when_latest_is_unrelated_role() {
        let s = snap(vec![ev(EndpointRole::Withdrawal, 100)]);
        assert!(SequenceTimingClassifier.evaluate(&s, 100, &cfg_with(1500)).is_none());
    }

    #[test]
    fn missing_predecessor_returns_none() {
        // Latest is OTP but no prior Login event in window.
        let s = snap(vec![ev(EndpointRole::Otp, 500)]);
        assert!(SequenceTimingClassifier.evaluate(&s, 500, &cfg_with(1500)).is_none());
    }

    #[test]
    fn no_config_block_disables_classifier() {
        let s = snap(vec![ev(EndpointRole::Login, 0), ev(EndpointRole::Otp, 50)]);
        assert!(
            SequenceTimingClassifier
                .evaluate(&s, 50, &TxVelocityConfig::default())
                .is_none()
        );
    }
}
