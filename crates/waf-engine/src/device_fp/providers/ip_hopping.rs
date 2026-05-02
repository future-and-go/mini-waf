//! Same fingerprint observed across multiple IPs in a window.
//!
//! Reads `Observation.distinct_ips_in_window` populated upstream by an
//! `IdentityStore::observe` call. Emits `Signal::IpHopping` when the
//! window count exceeds `max_distinct_ips`.

use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Debug, Clone, Copy)]
pub struct IpHoppingProvider {
    pub max_distinct_ips: u16,
}

impl Default for IpHoppingProvider {
    fn default() -> Self {
        Self { max_distinct_ips: 3 }
    }
}

impl IpHoppingProvider {
    #[must_use]
    pub const fn new(max_distinct_ips: u16) -> Self {
        Self { max_distinct_ips }
    }
}

impl SignalProvider for IpHoppingProvider {
    fn name(&self) -> &'static str {
        "ip_hopping"
    }
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let Some(obs) = ctx.observation else {
            return Vec::new();
        };
        if obs.distinct_ips_in_window > self.max_distinct_ips {
            vec![Signal::IpHopping {
                distinct_ips: obs.distinct_ips_in_window,
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::{FpKey, Observation};
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn no_signal_below_threshold() {
        let p = IpHoppingProvider::new(3);
        let obs = Observation {
            distinct_ips_in_window: 3,
            ..Observation::default()
        };
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key).with_observation(&obs);
        assert!(p.evaluate(&ctx).is_empty());
    }

    #[test]
    fn signal_above_threshold() {
        let p = IpHoppingProvider::new(3);
        let obs = Observation {
            distinct_ips_in_window: 5,
            ..Observation::default()
        };
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key).with_observation(&obs);
        let s = p.evaluate(&ctx);
        assert_eq!(s.len(), 1);
        assert!(matches!(s[0], Signal::IpHopping { distinct_ips: 5 }));
    }

    #[test]
    fn no_signal_when_observation_missing() {
        let p = IpHoppingProvider::new(3);
        let conn = ConnCtx::new();
        let key = FpKey::default();
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key);
        assert!(p.evaluate(&ctx).is_empty());
    }
}
