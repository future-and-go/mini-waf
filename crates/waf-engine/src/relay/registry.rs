//! FR-007 phase-01 — provider registry.
//!
//! Strategy + Registry pattern: `register()` is called at startup based on
//! `signals.enabled`; `dispatch()` is the per-request fan-out.

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::relay::config::{AsnConfig, RelayConfig, TorConfig};
use crate::relay::intel::{AsnDb, DatacenterSet, EmptyAsnDb, asn_feed::IpinfoLiteMmdb, asn_feed_iptoasn::IptoasnTsv};
use crate::relay::providers::{AsnClassifier, ProxyChainAnalyzer, TorExitMatcher, TorSet, XffValidator};
use crate::relay::signal::{RelayCtx, Signal, SignalProvider};

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

    /// Run every registered provider against `ctx`, concatenating their
    /// signals in registration order. Empty registry → empty Vec (fail-open
    /// at config layer; runtime fail-close decisions live in phases 02-04).
    pub fn dispatch(&self, ctx: &RelayCtx<'_>) -> Vec<Signal> {
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

    /// Build a registry from a validated `RelayConfig`. Each entry in
    /// `signals.enabled` selects a concrete provider; unknown names error
    /// (fail-closed at boot, fail-open at request time per phase-01).
    pub fn from_config(cfg: &RelayConfig) -> anyhow::Result<Self> {
        let mut reg = Self::new();
        for name in &cfg.signals.enabled {
            match name.as_str() {
                "xff_validator" => {
                    let p = XffValidator::new(&cfg.headers.forwarded_for, cfg.trusted_proxies.clone())?;
                    reg.register(Box::new(p));
                }
                "proxy_chain" => {
                    let p = ProxyChainAnalyzer::new(
                        &cfg.headers.forwarded_for,
                        cfg.trusted_proxies.clone(),
                        cfg.max_chain_depth,
                    )?;
                    reg.register(Box::new(p));
                }
                "asn_classifier" => {
                    reg.register(Box::new(build_asn_classifier(&cfg.asn)?));
                }
                "tor_exit" => {
                    reg.register(Box::new(build_tor_exit(&cfg.tor)));
                }
                other => {
                    anyhow::bail!("unknown signal provider in signals.enabled: {other:?}");
                }
            }
        }
        Ok(reg)
    }
}

/// Resolve the configured ASN backend. Selection rules:
/// - `provider == "iptoasn"` → load TSV from `mmdb_path` (path is reused).
/// - `provider == "ipinfo_lite"` or unset, `mmdb_path` set → mmdb reader.
/// - Otherwise → `EmptyAsnDb` (degraded; every lookup → `AsnUnknown`).
///
/// Errors propagate ONLY when `cfg.fail_close == true`; the default is to
/// warn and degrade so an operator with a misconfigured intel feed does
/// not lose the proxy and gateway entirely.
fn build_asn_classifier(cfg: &AsnConfig) -> anyhow::Result<AsnClassifier> {
    let db: Box<dyn AsnDb> = match (cfg.provider.as_deref(), cfg.mmdb_path.as_ref()) {
        (Some("iptoasn"), Some(path)) => match IptoasnTsv::load(path) {
            Ok(d) => Box::new(d),
            Err(e) if cfg.fail_close => return Err(e.context("ASN fail-close (iptoasn)")),
            Err(e) => {
                tracing::warn!(error = %e, "ASN iptoasn TSV load failed; degrading to empty DB");
                Box::new(EmptyAsnDb)
            }
        },
        (Some("ipinfo_lite") | None, Some(path)) => match IpinfoLiteMmdb::open(path) {
            Ok(d) => Box::new(d),
            Err(e) if cfg.fail_close => return Err(e.context("ASN fail-close (ipinfo_lite)")),
            Err(e) => {
                tracing::warn!(error = %e, "ASN mmdb load failed; degrading to empty DB");
                Box::new(EmptyAsnDb)
            }
        },
        (Some(other), _) => {
            anyhow::bail!("unknown asn.provider {other:?} (expected ipinfo_lite|iptoasn)");
        }
        (_, None) => {
            if cfg.fail_close {
                anyhow::bail!("asn.fail_close=true but no asn.mmdb_path configured");
            }
            Box::new(EmptyAsnDb)
        }
    };

    let dc = match DatacenterSet::load(&cfg.datacenter_lists) {
        Ok(s) => Arc::new(s),
        Err(e) if cfg.fail_close => return Err(e.context("datacenter_lists fail-close")),
        Err(e) => {
            tracing::warn!(error = %e, "datacenter_lists load failed; using empty set");
            Arc::new(DatacenterSet::default())
        }
    };

    Ok(AsnClassifier::new(db, dc))
}

/// Build a `TorExitMatcher`.
///
/// Missing list path or load error → empty set + warn (graceful
/// degradation; brainstorm §4.9). The phase-04 refresh task or phase-05
/// watcher repopulates the set asynchronously.
fn build_tor_exit(cfg: &TorConfig) -> TorExitMatcher {
    let initial = cfg
        .list_path
        .as_ref()
        .map_or_else(TorSet::default, |path| match TorSet::load(path) {
            Ok(set) => set,
            Err(e) => {
                tracing::warn!(error = %e, path = %path.display(), "Tor list load failed; starting with empty set");
                TorSet::default()
            }
        });
    TorExitMatcher::new(std::sync::Arc::new(ArcSwap::from(std::sync::Arc::new(initial))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Instant;

    struct Fixed(&'static str, Vec<Signal>);
    impl SignalProvider for Fixed {
        fn name(&self) -> &'static str {
            self.0
        }
        fn evaluate(&self, _ctx: &RelayCtx<'_>) -> Vec<Signal> {
            self.1.clone()
        }
    }

    #[test]
    fn empty_registry_emits_no_signals() {
        let reg = ProviderRegistry::new();
        let headers = http::HeaderMap::new();
        let ctx = RelayCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), &headers, Instant::now());
        assert!(reg.dispatch(&ctx).is_empty());
        assert!(reg.is_empty());
    }

    #[test]
    fn from_config_wires_known_providers() {
        let yaml = r#"
relay_detection:
  trusted_proxies: ["10.0.0.0/8"]
  max_chain_depth: 3
  signals:
    enabled: ["xff_validator", "proxy_chain"]
"#;
        let cfg = RelayConfig::from_yaml_str(yaml).expect("parse");
        let reg = ProviderRegistry::from_config(&cfg).expect("build");
        assert_eq!(reg.names(), vec!["xff_validator", "proxy_chain"]);
    }

    #[test]
    fn from_config_wires_asn_classifier_default_empty_db() {
        let yaml = r#"
relay_detection:
  signals:
    enabled: ["asn_classifier"]
"#;
        let cfg = RelayConfig::from_yaml_str(yaml).expect("parse");
        let reg = ProviderRegistry::from_config(&cfg).expect("build");
        assert_eq!(reg.names(), vec!["asn_classifier"]);
    }

    #[test]
    fn from_config_asn_classifier_fail_close_without_path_errors() {
        let yaml = r#"
relay_detection:
  asn:
    fail_close: true
  signals:
    enabled: ["asn_classifier"]
"#;
        let cfg = RelayConfig::from_yaml_str(yaml).expect("parse");
        assert!(ProviderRegistry::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_asn_classifier_unknown_provider_errors() {
        let yaml = r#"
relay_detection:
  asn:
    provider: "mystery"
  signals:
    enabled: ["asn_classifier"]
"#;
        let cfg = RelayConfig::from_yaml_str(yaml).expect("parse");
        assert!(ProviderRegistry::from_config(&cfg).is_err());
    }

    #[test]
    fn from_config_rejects_unknown_provider() {
        let yaml = r#"
relay_detection:
  signals:
    enabled: ["mystery_box"]
"#;
        let cfg = RelayConfig::from_yaml_str(yaml).expect("parse");
        assert!(ProviderRegistry::from_config(&cfg).is_err());
    }

    #[test]
    fn dispatch_concatenates_in_order() {
        let mut reg = ProviderRegistry::new();
        reg.register(Box::new(Fixed("a", vec![Signal::XffMalformed])));
        reg.register(Box::new(Fixed("b", vec![Signal::TorExit])));
        let headers = http::HeaderMap::new();
        let ctx = RelayCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), &headers, Instant::now());
        let out = reg.dispatch(&ctx);
        assert_eq!(out, vec![Signal::XffMalformed, Signal::TorExit]);
        assert_eq!(reg.names(), vec!["a", "b"]);
        assert_eq!(reg.len(), 2);
    }
}
