//! FR-010 device fingerprinting subsystem.
//!
//! Mirrors the FR-007 `relay/` Strategy + Registry pattern: a top-level
//! [`DeviceFpDetector`] owns an `ArcSwap<DeviceFpConfig>` snapshot and a
//! [`ProviderRegistry`]; signal providers are pure data + trait-object
//! plug-ins driven by YAML.
//!
//! Phase ladder (`plans/260501-2005-fr010-device-fingerprinting/plan.md`):
//! - Phase 01 ✓ Pingora L4 inspector primitives (capture stubs).
//! - Phase 02 ◄ Module skeleton, traits, YAML schema, hot reload (THIS).
//! - Phase 03+ capture impls, fingerprint algos, identity store, signals.

pub mod aggregator;
pub mod capture;
pub mod config;
pub mod fingerprint;
pub mod identity;
pub mod providers;
pub mod registry;
pub mod reload;
pub mod signal;
pub mod types;

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;

pub use aggregator::{NoopAggregator, RiskAggregator};
pub use config::{
    CaptureConfig, DeviceFpConfig, DeviceFpDocument, H2CaptureConfig, ProviderConfig,
    RedisStoreConfig, StoreBackend, StoreConfig, TlsCaptureConfig,
};
pub use fingerprint::FingerprintProvider;
pub use identity::{IdentityStore, MemoryIdentityStore};
pub use providers::SignalProvider;
pub use registry::ProviderRegistry;
pub use reload::{DEFAULT_DEBOUNCE_MS, DeviceFpReloader};
pub use signal::{H2AnomalyReason, Signal};
pub use types::{
    DeviceCtx, DeviceDerived, DeviceIdentity, FingerprintValue, FpKey, IdentityRecord, Observation,
};

/// Top-level facade.
///
/// Owns the active config snapshot + provider registry. Hot-swap of `cfg`
/// is via `ArcSwap`; the registry is rebuilt on reload, not mutated in
/// place — in-flight requests keep using the old registry until they
/// release their `Arc` borrow.
pub struct DeviceFpDetector {
    cfg: Arc<ArcSwap<DeviceFpConfig>>,
    registry: ProviderRegistry,
}

impl DeviceFpDetector {
    #[must_use]
    pub fn new(cfg: Arc<DeviceFpConfig>, registry: ProviderRegistry) -> Self {
        Self {
            cfg: Arc::new(ArcSwap::from(cfg)),
            registry,
        }
    }

    /// Empty detector — used at boot before YAML loads, or on degraded
    /// startup. Emits no signals (fail-open at config layer, brainstorm §4.9).
    #[must_use]
    pub fn empty() -> Self {
        Self::new(Arc::new(DeviceFpConfig::default()), ProviderRegistry::new())
    }

    /// Load from a YAML path. Validates + builds the registry. Returns
    /// the detector plus the [`ArcSwap`] handle so the reloader can swap
    /// in new snapshots without touching the detector.
    pub fn from_path(path: &Path) -> anyhow::Result<(Self, Arc<ArcSwap<DeviceFpConfig>>)> {
        let cfg = DeviceFpConfig::from_path(path)?;
        let registry = ProviderRegistry::from_config(&cfg)?;
        let swap = Arc::new(ArcSwap::from(cfg));
        let detector = Self {
            cfg: Arc::clone(&swap),
            registry,
        };
        Ok((detector, swap))
    }

    #[must_use]
    pub fn config(&self) -> Arc<DeviceFpConfig> {
        self.cfg.load_full()
    }

    #[must_use]
    pub const fn registry(&self) -> &ProviderRegistry {
        &self.registry
    }

    /// Phase-02 evaluator: dispatches the (empty) registry against `ctx`.
    /// Phase-04 populates `key` from the captured raw bytes; phase-06 fills
    /// the registry with the five concrete providers.
    pub fn evaluate(&self, ctx: &DeviceCtx<'_>) -> DeviceIdentity {
        let signals = self.registry.dispatch(ctx);
        DeviceIdentity {
            key: Arc::new(ctx.key.clone()),
            signals,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn empty_detector_emits_no_signals() {
        let det = DeviceFpDetector::empty();
        let conn = ConnCtx::new();
        let key = FpKey {
            ja3: None,
            ja4: None,
            h2_akamai: None,
        };
        let ctx = DeviceCtx::new(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn, &key);
        let id = det.evaluate(&ctx);
        assert!(id.signals.is_empty());
    }

    #[test]
    fn from_path_loads_and_builds() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("device-fp.yaml");
        std::fs::write(&p, "device_fp:\n  enabled: true\n").unwrap();
        let (det, swap) = DeviceFpDetector::from_path(&p).unwrap();
        assert!(det.config().enabled);
        assert!(swap.load().enabled);
    }
}
