//! FR-007 — Relay / proxy detection subsystem.
//!
//! Phase-01 wires only the public data model, traits, YAML parser, and a
//! `RelayDetector` facade stub returning a minimal `ClientIdentity`.
//! Phases 02-04 register concrete `SignalProvider`s; phase-05 adds reload.

pub mod audit_map;
pub mod config;
pub mod intel;
pub mod providers;
pub mod registry;
pub mod reload;
pub mod signal;

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use http::HeaderMap;
use tokio::task::JoinHandle;

pub use config::{
    AsnConfig, HeaderConfig, RefreshConfig, RelayConfig, RelayDetectionDocument, SignalConfig, TorConfig,
};
pub use intel::{AsnDb, AsnRecord, DatacenterSet, EmptyAsnDb, IntelProvider, RefreshOutcome};
pub use registry::ProviderRegistry;
pub use signal::{AsnClass, ClientIdentity, RelayCtx, Signal, SignalProvider};

/// Top-level facade. Owns the active config snapshot + provider registry.
/// Hot-swap of `cfg` is via `ArcSwap` (phase-05); registry is rebuilt on
/// reload, not mutated in place.
pub struct RelayDetector {
    cfg: Arc<ArcSwap<RelayConfig>>,
    registry: ProviderRegistry,
}

impl RelayDetector {
    #[must_use]
    pub fn new(cfg: Arc<RelayConfig>, registry: ProviderRegistry) -> Self {
        Self {
            cfg: Arc::new(ArcSwap::from(cfg)),
            registry,
        }
    }

    /// Empty detector — used at boot before YAML loads, or on degraded
    /// startup. Emits no signals (fail-open at config layer).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Arc::new(RelayConfig::default()), ProviderRegistry::new())
    }

    #[must_use]
    pub fn config(&self) -> Arc<RelayConfig> {
        self.cfg.load_full()
    }

    /// Spawn one background refresh loop per supplied intel provider.
    ///
    /// Caller owns the returned handles — drop or `abort()` to stop a
    /// loop. Each loop survives transient `Failed` outcomes (logs + waits
    /// for next interval); only a panic in the provider would terminate
    /// the loop, which `tokio` reports via the `JoinHandle`.
    ///
    /// Phase-04 ships the spawn primitive; phase-05's watcher decides
    /// which providers are active.
    pub fn start_refresh_tasks(providers: Vec<(Arc<dyn IntelProvider>, Duration)>) -> Vec<JoinHandle<()>> {
        providers
            .into_iter()
            .map(|(provider, interval)| {
                tokio::spawn(async move {
                    intel_refresh_loop(provider, interval).await;
                })
            })
            .collect()
    }

    /// Phase-01 stub: returns `peer_ip` with `AsnClass::Unknown` plus whatever
    /// signals the (empty) registry produces. Phases 02-04 enrich this.
    pub fn evaluate(&self, peer_ip: IpAddr, headers: &HeaderMap) -> ClientIdentity {
        let ctx = RelayCtx::new(peer_ip, headers, Instant::now());
        let signals = self.registry.dispatch(&ctx);
        let real_ip = ctx.derived().map_or(peer_ip, |d| d.real_ip);
        ClientIdentity {
            real_ip,
            asn: None,
            asn_class: AsnClass::Unknown,
            signals,
        }
    }
}

/// Periodic refresh: one tick per `interval`, log + retain on failure.
async fn intel_refresh_loop(provider: Arc<dyn IntelProvider>, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    // Skip the immediate first tick — boot loaders already do an eager
    // load; first refresh fires after `interval` elapses.
    ticker.tick().await;
    loop {
        ticker.tick().await;
        match provider.refresh().await {
            Ok(RefreshOutcome::Updated) => {
                tracing::info!(provider = provider.name(), "intel updated");
            }
            Ok(RefreshOutcome::NotModified) => {}
            Ok(RefreshOutcome::Failed(e)) => {
                tracing::warn!(provider = provider.name(), error = %e, "intel refresh failed; retaining last good");
            }
            Err(e) => {
                tracing::warn!(provider = provider.name(), error = %e, "intel refresh hard error");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn empty_detector_yields_unknown_identity() {
        let det = RelayDetector::empty();
        let headers = HeaderMap::new();
        let id = det.evaluate(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)), &headers);
        assert_eq!(id.asn_class, AsnClass::Unknown);
        assert!(id.signals.is_empty());
        assert!(id.asn.is_none());
    }
}
