//! Withdrawal-velocity classifier.
//!
//! Fires when an actor's count of `Withdrawal` events inside the rolling
//! `window_ms` window exceeds `max_count`. Window is anchored at `now_ms`,
//! not at the most-recent event, so a long-idle actor with one fresh
//! withdrawal isn't compared against ancient history.

use crate::checks::tx_velocity::EndpointRole;
use crate::checks::tx_velocity::classifier::Classifier;
use crate::checks::tx_velocity::config::{TxVelocityConfig, VelocityCfg};
use crate::checks::tx_velocity::recorder::ActorTxSnapshot;
use crate::device_fp::signal::Signal;

pub struct WithdrawalVelocityClassifier;

impl Classifier for WithdrawalVelocityClassifier {
    fn name(&self) -> &'static str {
        "withdrawal_velocity"
    }

    fn evaluate(&self, snap: &ActorTxSnapshot, now_ms: u64, cfg: &TxVelocityConfig) -> Option<Signal> {
        let vcfg = cfg.classifiers.withdrawal_velocity.as_ref()?;
        evaluate_velocity(snap, now_ms, vcfg, EndpointRole::Withdrawal)
            .map(|(count, window_sec)| Signal::WithdrawalVelocity { count, window_sec })
    }
}

/// Shared body — counts events of `role` in the trailing window. Returned
/// `Some((count, window_sec))` only when the threshold is exceeded.
pub(super) fn evaluate_velocity(
    snap: &ActorTxSnapshot,
    now_ms: u64,
    cfg: &VelocityCfg,
    role: EndpointRole,
) -> Option<(u32, u32)> {
    if cfg.window_ms == 0 {
        return None;
    }
    let cutoff = now_ms.saturating_sub(cfg.window_ms);
    let count: u32 = snap
        .events
        .iter()
        .filter(|e| e.role == role && e.ts_ms >= cutoff)
        .count()
        .try_into()
        .unwrap_or(u32::MAX);
    if count > cfg.max_count {
        // ms → sec for the signal payload (round up so 500 ms → 1 s).
        let window_sec: u32 = u32::try_from(cfg.window_ms.div_ceil(1_000)).unwrap_or(u32::MAX);
        Some((count, window_sec))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::tx_velocity::Event;
    use crate::checks::tx_velocity::config::ClassifierConfigs;

    fn cfg_with(max_count: u32, window_ms: u64) -> TxVelocityConfig {
        TxVelocityConfig {
            classifiers: ClassifierConfigs {
                withdrawal_velocity: Some(VelocityCfg { max_count, window_ms }),
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

    fn w(ts_ms: u64) -> Event {
        Event {
            role: EndpointRole::Withdrawal,
            ts_ms,
            ok: true,
        }
    }

    #[test]
    fn fires_above_threshold() {
        let s = snap(vec![w(100), w(200), w(300), w(400)]);
        let out = WithdrawalVelocityClassifier.evaluate(&s, 500, &cfg_with(3, 60_000));
        assert!(matches!(
            out,
            Some(Signal::WithdrawalVelocity {
                count: 4,
                window_sec: 60
            })
        ));
    }

    #[test]
    fn quiet_at_threshold() {
        let s = snap(vec![w(100), w(200), w(300)]);
        let out = WithdrawalVelocityClassifier.evaluate(&s, 500, &cfg_with(3, 60_000));
        assert!(out.is_none());
    }

    #[test]
    fn excludes_events_outside_window() {
        // Only the freshest event sits inside the 1 s window.
        let s = snap(vec![w(100), w(200), w(300), w(60_500)]);
        let out = WithdrawalVelocityClassifier.evaluate(&s, 60_500, &cfg_with(0, 1_000));
        assert!(matches!(
            out,
            Some(Signal::WithdrawalVelocity {
                count: 1,
                window_sec: 1
            })
        ));
    }

    #[test]
    fn ignores_other_roles() {
        let s = snap(vec![
            Event {
                role: EndpointRole::Deposit,
                ts_ms: 100,
                ok: true,
            },
            Event {
                role: EndpointRole::Deposit,
                ts_ms: 200,
                ok: true,
            },
            w(300),
        ]);
        let out = WithdrawalVelocityClassifier.evaluate(&s, 400, &cfg_with(2, 60_000));
        assert!(out.is_none());
    }

    #[test]
    fn no_config_block_disables_classifier() {
        let s = snap(vec![w(100), w(200), w(300), w(400)]);
        assert!(
            WithdrawalVelocityClassifier
                .evaluate(&s, 500, &TxVelocityConfig::default())
                .is_none()
        );
    }
}
