//! FR-010 phase-02 — provider registry.
//!
//! Strategy + Registry pattern (mirrors `relay::registry`). `register()`
//! adds a [`SignalProvider`]; `dispatch()` is the per-request fan-out.
//! `from_config()` returns an empty registry in phase-02 — concrete
//! provider construction lands in phase-06.

use crate::device_fp::config::DeviceFpConfig;
use crate::device_fp::providers::SignalProvider;
use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

#[derive(Default)]
pub struct ProviderRegistry {
    providers: Vec<Box<dyn SignalProvider>>,
}

impl ProviderRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, provider: Box<dyn SignalProvider>) {
        self.providers.push(provider);
    }

    /// Run every registered provider and concat their signals in
    /// registration order. Empty registry → empty Vec (fail-open).
    pub fn dispatch(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal> {
        let mut out = Vec::new();
        for p in &self.providers {
            out.extend(p.evaluate(ctx));
        }
        out
    }

    #[must_use]
    pub fn names(&self) -> Vec<&'static str> {
        self.providers.iter().map(|p| p.name()).collect()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.providers.len()
    }

    /// Build a registry from a validated [`DeviceFpConfig`].
    ///
    /// Phase-02 returns an empty registry regardless of config — concrete
    /// providers (`fp_conflict`, `ip_hopping`, `ua_entropy`,
    /// `ua_blocklist`, `h2_anomaly`) ship in phase-06. Unknown provider
    /// names already error at `from_yaml_str` boundary; this method only
    /// fails if construction itself fails.
    pub fn from_config(_cfg: &DeviceFpConfig) -> anyhow::Result<Self> {
        Ok(Self::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use crate::device_fp::types::FpKey;
    use std::net::{IpAddr, Ipv4Addr};

    struct Fixed(&'static str, Vec<Signal>);
    impl SignalProvider for Fixed {
        fn name(&self) -> &'static str {
            self.0
        }
        fn evaluate(&self, _ctx: &DeviceCtx<'_>) -> Vec<Signal> {
            self.1.clone()
        }
    }

    #[test]
    fn empty_registry_emits_no_signals() {
        let reg = ProviderRegistry::new();
        let conn = ConnCtx::new();
        let key = FpKey {
            ja3: None,
            ja4: None,
            h2_akamai: None,
        };
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key);
        assert!(reg.dispatch(&ctx).is_empty());
        assert!(reg.is_empty());
    }

    #[test]
    fn dispatch_concatenates_in_order() {
        let mut reg = ProviderRegistry::new();
        reg.register(Box::new(Fixed(
            "a",
            vec![Signal::IpHopping { distinct_ips: 4 }],
        )));
        reg.register(Box::new(Fixed(
            "b",
            vec![Signal::LowEntropyUa { entropy_x100: 100 }],
        )));
        let conn = ConnCtx::new();
        let key = FpKey {
            ja3: None,
            ja4: None,
            h2_akamai: None,
        };
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key);
        let out = reg.dispatch(&ctx);
        assert_eq!(out.len(), 2);
        assert_eq!(reg.names(), vec!["a", "b"]);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn from_config_phase02_returns_empty() {
        let cfg = DeviceFpConfig::from_yaml_str("device_fp:\n  enabled: true\n").unwrap();
        let reg = ProviderRegistry::from_config(&cfg).unwrap();
        assert!(reg.is_empty());
    }
}
