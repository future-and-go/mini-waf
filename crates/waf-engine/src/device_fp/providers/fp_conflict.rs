//! Same fingerprint observed under multiple distinct User-Agents.
//!
//! Reads `Observation.distinct_uas_in_window` from the identity store and
//! emits `Signal::FpConflict` when it exceeds `max_distinct_uas`. Pairs
//! naturally with `IpHoppingProvider` — both consume the same observation
//! struct, no extra store needed.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Clone, Copy)]
pub struct FpConflictProvider {
    pub max_distinct_uas: u16,
}

impl Default for FpConflictProvider {
    fn default() -> Self {
        Self { max_distinct_uas: 2 }
    }
}

impl FpConflictProvider {
    #[must_use]
    pub const fn new(max_distinct_uas: u16) -> Self {
        Self { max_distinct_uas }
    }
}

impl SignalProvider for FpConflictProvider {
    fn name(&self) -> &'static str {
        "fp_conflict"
    }
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let Some(obs) = ctx.observation else {
            return Vec::new();
        };
        if obs.distinct_uas_in_window > self.max_distinct_uas {
            vec![Signal::FpConflict {
                distinct_uas: obs.distinct_uas_in_window,
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::trivially_copy_pass_by_ref)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::{FpKey, Observation};
    use std::net::{IpAddr, Ipv4Addr};

    fn eval(p: &FpConflictProvider, obs: &Observation) -> Vec<Signal> {
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key).with_observation(obs);
        p.evaluate(&ctx)
    }

    #[test]
    fn no_signal_below_threshold() {
        let p = FpConflictProvider::new(2);
        let obs = Observation {
            distinct_uas_in_window: 2,
            ..Observation::default()
        };
        assert!(eval(&p, &obs).is_empty());
    }

    #[test]
    fn signal_above_threshold() {
        let p = FpConflictProvider::new(2);
        let obs = Observation {
            distinct_uas_in_window: 5,
            ..Observation::default()
        };
        let s = eval(&p, &obs);
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0], Signal::FpConflict { distinct_uas: 5 }));
    }

    #[test]
    fn no_signal_when_observation_missing() {
        let p = FpConflictProvider::new(2);
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key);
        assert!(p.evaluate(&ctx).is_empty());
    }
}
