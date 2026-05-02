//! FR-010 phase-02 — provider registry.
//!
//! Strategy + Registry pattern (mirrors `relay::registry`). `register()`
//! adds a [`SignalProvider`]; `dispatch()` is the per-request fan-out.
//! `from_config()` returns an empty registry in phase-02 — concrete
//! provider construction lands in phase-06.

use crate::device_fp::config::{DeviceFpConfig, ProviderConfig};
use crate::device_fp::providers::{
    FpConflictProvider, H2AnomalyProvider, IpHoppingProvider, SignalProvider, UaBlocklistProvider,
    UaEntropyProvider,
};
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
    /// Construction errors (e.g. invalid blocklist regex) bubble up. Names
    /// not recognised by this build are logged at `warn` and skipped — a
    /// future binary may know providers this one doesn't, and we do not
    /// want config-driven boot failures.
    pub fn from_config(cfg: &DeviceFpConfig) -> anyhow::Result<Self> {
        let mut reg = Self::new();
        for p in &cfg.providers {
            if let Some(boxed) = build_provider(p)? {
                reg.register(boxed);
            } else {
                tracing::warn!(provider = %p.name, "device_fp: unknown provider, skipping");
            }
        }
        Ok(reg)
    }
}

fn build_provider(p: &ProviderConfig) -> anyhow::Result<Option<Box<dyn SignalProvider>>> {
    let boxed: Box<dyn SignalProvider> = match p.name.as_str() {
        "ip_hopping" => Box::new(IpHoppingProvider::new(p.max_distinct_ips.unwrap_or(3))),
        "ua_entropy" => Box::new(UaEntropyProvider::new(p.min_entropy_x100.unwrap_or(250))),
        "ua_blocklist" => Box::new(UaBlocklistProvider::new(p.blocklist_patterns.clone())?),
        "h2_anomaly" => Box::new(H2AnomalyProvider::new(false)),
        "fp_conflict" => Box::new(FpConflictProvider::new(p.max_distinct_uas.unwrap_or(2))),
        _ => return Ok(None),
    };
    Ok(Some(boxed))
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
    fn from_config_no_providers_returns_empty() {
        let cfg = DeviceFpConfig::from_yaml_str("device_fp:\n  enabled: true\n").unwrap();
        let reg = ProviderRegistry::from_config(&cfg).unwrap();
        assert!(reg.is_empty());
    }

    #[test]
    fn from_config_builds_known_providers() {
        let yaml = r"
device_fp:
  enabled: true
  providers:
    - name: ip_hopping
      max_distinct_ips: 4
    - name: ua_entropy
      min_entropy_x100: 300
    - name: ua_blocklist
      blocklist_patterns: ['(?i)curl/']
    - name: h2_anomaly
    - name: fp_conflict
      max_distinct_uas: 3
";
        let cfg = DeviceFpConfig::from_yaml_str(yaml).unwrap();
        let reg = ProviderRegistry::from_config(&cfg).unwrap();
        assert_eq!(reg.len(), 5);
        assert_eq!(
            reg.names(),
            vec!["ip_hopping", "ua_entropy", "ua_blocklist", "h2_anomaly", "fp_conflict"]
        );
    }

    #[test]
    fn from_config_skips_unknown_provider() {
        let yaml = r"
device_fp:
  providers:
    - name: ip_hopping
    - name: not_a_real_provider
";
        let cfg = DeviceFpConfig::from_yaml_str(yaml).unwrap();
        let reg = ProviderRegistry::from_config(&cfg).unwrap();
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.names(), vec!["ip_hopping"]);
    }

    #[test]
    fn from_config_propagates_blocklist_error() {
        let yaml = r"
device_fp:
  providers:
    - name: ua_blocklist
      blocklist_patterns: ['(.*)*evil']
";
        let cfg = DeviceFpConfig::from_yaml_str(yaml).unwrap();
        assert!(ProviderRegistry::from_config(&cfg).is_err());
    }
}
