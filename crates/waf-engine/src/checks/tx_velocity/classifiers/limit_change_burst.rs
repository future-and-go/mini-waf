//! Limit-change-burst classifier.
//!
//! Same shape as withdrawal-velocity but watches `LimitChange` events with
//! its own threshold pair. Built on the shared
//! `withdrawal_velocity::evaluate_velocity` helper to avoid duplicating the
//! window arithmetic.

use crate::checks::tx_velocity::EndpointRole;
use crate::checks::tx_velocity::classifier::Classifier;
use crate::checks::tx_velocity::config::TxVelocityConfig;
use crate::checks::tx_velocity::recorder::ActorTxSnapshot;
use crate::device_fp::signal::Signal;

use super::withdrawal_velocity::evaluate_velocity;

pub struct LimitChangeBurstClassifier;

impl Classifier for LimitChangeBurstClassifier {
    fn name(&self) -> &'static str {
        "limit_change_burst"
    }

    fn evaluate(&self, snap: &ActorTxSnapshot, now_ms: u64, cfg: &TxVelocityConfig) -> Option<Signal> {
        let vcfg = cfg.classifiers.limit_change_velocity.as_ref()?;
        evaluate_velocity(snap, now_ms, vcfg, EndpointRole::LimitChange)
            .map(|(count, window_sec)| Signal::LimitChangeBurst { count, window_sec })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::Event;
    use crate::checks::tx_velocity::config::{ClassifierConfigs, VelocityCfg};

    fn cfg_with(max_count: u32, window_ms: u64) -> TxVelocityConfig {
        TxVelocityConfig {
            classifiers: ClassifierConfigs {
                limit_change_velocity: Some(VelocityCfg { max_count, window_ms }),
                ..ClassifierConfigs::default()
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

    fn lc(ts_ms: u64) -> Event {
        Event {
            role: EndpointRole::LimitChange,
            ts_ms,
            ok: true,
        }
    }

    #[test]
    fn fires_above_threshold() {
        let s = snap(vec![lc(0), lc(100), lc(200), lc(300)]);
        let out = LimitChangeBurstClassifier.evaluate(&s, 400, &cfg_with(2, 60_000));
        assert!(matches!(
            out,
            Some(Signal::LimitChangeBurst {
                count: 4,
                window_sec: 60
            })
        ));
    }

    #[test]
    fn quiet_at_threshold() {
        let s = snap(vec![lc(0), lc(100)]);
        let out = LimitChangeBurstClassifier.evaluate(&s, 200, &cfg_with(2, 60_000));
        assert!(out.is_none());
    }

    #[test]
    fn ignores_other_roles() {
        let s = snap(vec![
            Event {
                role: EndpointRole::Withdrawal,
                ts_ms: 100,
                ok: true,
            },
            Event {
                role: EndpointRole::Withdrawal,
                ts_ms: 200,
                ok: true,
            },
            Event {
                role: EndpointRole::Withdrawal,
                ts_ms: 300,
                ok: true,
            },
        ]);
        assert!(
            LimitChangeBurstClassifier
                .evaluate(&s, 400, &cfg_with(1, 60_000))
                .is_none()
        );
    }

    #[test]
    fn no_config_block_disables_classifier() {
        let s = snap(vec![lc(0), lc(100), lc(200), lc(300)]);
        assert!(
            LimitChangeBurstClassifier
                .evaluate(&s, 400, &TxVelocityConfig::default())
                .is_none()
        );
    }
}
