//! FR-010 device fingerprinting subsystem.
//!
//! Mirrors the FR-007 `relay/` Strategy + Registry pattern: a top-level
//! [`DeviceFpDetector`] owns an `ArcSwap<DeviceFpConfig>` snapshot and a
//! [`ProviderRegistry`]; signal providers are pure data + trait-object
//! plug-ins driven by YAML.
//!
//! Phase ladder (`plans/260501-2005-fr010-device-fingerprinting/plan.md`):
//! - Phase 01 ✓ Pingora L4 inspector primitives (capture stubs).
//! - Phase 02 ✓ Module skeleton, traits, YAML schema, hot reload.
//! - Phase 07 ◄ End-to-end `process()` + risk-aggregator wiring (THIS).

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

use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;

pub use aggregator::{AggregatorSubmission, LoggingAggregator, NoopAggregator, RiskAggregator};
pub use config::{
    CaptureConfig, DeviceFpConfig, DeviceFpDocument, H2CaptureConfig, ProviderConfig, RedisStoreConfig, StoreBackend,
    StoreConfig, TlsCaptureConfig,
};
pub use fingerprint::{FingerprintProvider, FingerprintRegistry, H2AkamaiFingerprint, Ja3Fingerprint, Ja4Fingerprint};
pub use identity::{IdentityStore, MemoryIdentityStore};
pub use providers::SignalProvider;
pub use registry::ProviderRegistry;
pub use reload::{DEFAULT_DEBOUNCE_MS, DeviceFpReloader};
pub use signal::{H2AnomalyReason, Signal};
pub use types::{DeviceCtx, DeviceDerived, DeviceIdentity, FingerprintValue, FpKey, IdentityRecord, Observation};

use crate::device_fp::capture::ConnCtx;

/// Top-level facade.
///
/// Owns the active config snapshot + provider registry. Hot-swap of `cfg`
/// is via `ArcSwap`; the registry is rebuilt on reload, not mutated in
/// place — in-flight requests keep using the old registry until they
/// release their `Arc` borrow.
pub struct DeviceFpDetector {
    cfg: Arc<ArcSwap<DeviceFpConfig>>,
    registry: ProviderRegistry,
    fingerprints: FingerprintRegistry,
    store: Option<Arc<dyn IdentityStore>>,
    aggregator: Arc<dyn RiskAggregator>,
}

impl DeviceFpDetector {
    #[must_use]
    pub fn new(cfg: Arc<DeviceFpConfig>, registry: ProviderRegistry) -> Self {
        Self {
            cfg: Arc::new(ArcSwap::from(cfg)),
            registry,
            fingerprints: FingerprintRegistry::new(),
            store: None,
            aggregator: Arc::new(NoopAggregator),
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
            fingerprints: FingerprintRegistry::new(),
            store: None,
            aggregator: Arc::new(NoopAggregator),
        };
        Ok((detector, swap))
    }

    /// Inject the persistent identity store (FR-010 phase-05+). When unset,
    /// `process()` skips observe and emits an empty [`Observation`].
    #[must_use]
    pub fn with_store(mut self, store: Arc<dyn IdentityStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Inject the risk aggregator (FR-025 plug-in). When unset, defaults to
    /// [`NoopAggregator`].
    #[must_use]
    pub fn with_aggregator(mut self, aggregator: Arc<dyn RiskAggregator>) -> Self {
        self.aggregator = aggregator;
        self
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
    /// Kept for callers that already own a `DeviceCtx` (tests, benches).
    /// Production callers should prefer [`Self::process`].
    pub fn evaluate(&self, ctx: &DeviceCtx<'_>) -> DeviceIdentity {
        let signals = self.registry.dispatch(ctx);
        DeviceIdentity {
            key: Arc::new(ctx.key.clone()),
            signals,
        }
    }

    /// End-to-end pipeline: assemble fingerprint key from raw capture →
    /// record observation in the identity store → dispatch signal providers
    /// → fire-and-forget submit to the risk aggregator → return resolved
    /// identity for downstream consumers (gateway request ctx).
    ///
    /// Fail-open everywhere: store / aggregator errors are logged at `warn`
    /// and the request proceeds. Empty `FpKey` (no fingerprint produced)
    /// skips observe but still runs providers — UA-only signals
    /// (blocklist, entropy) remain meaningful.
    pub async fn process(&self, peer_ip: IpAddr, user_agent: &str, conn: &ConnCtx) -> DeviceIdentity {
        let raw = conn.snapshot();
        let key = self.fingerprints.assemble(&raw);

        let observation = if let Some(store) = &self.store
            && !key.is_empty()
        {
            let ts = unix_now();
            match store.observe(&key, peer_ip, user_agent, ts).await {
                Ok(obs) => Some(obs),
                Err(err) => {
                    tracing::warn!(target: "device_fp::process", ?err, "identity-store observe failed; continuing without observation");
                    None
                }
            }
        } else {
            None
        };

        let mut ctx = DeviceCtx::new(peer_ip, user_agent, conn, &key);
        if let Some(obs) = observation.as_ref() {
            ctx = ctx.with_observation(obs);
        }

        let signals = self.registry.dispatch(&ctx);
        self.aggregator.submit(&key, &signals).await;

        DeviceIdentity {
            key: Arc::new(key),
            signals,
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().cast_signed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::capture::ConnCtx;
    use std::net::Ipv4Addr;

    #[test]
    fn empty_detector_emits_no_signals() {
        let det = DeviceFpDetector::empty();
        let conn = ConnCtx::new();
        let key = FpKey::default();
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

    #[tokio::test]
    async fn process_runs_aggregator_submit() {
        // No store, empty registry → empty signals. Verifies the wiring:
        // process() always reaches the aggregator, even with zero signals.
        let agg = Arc::new(LoggingAggregator::new(4));
        let det = DeviceFpDetector::empty().with_aggregator(agg.clone());
        let conn = ConnCtx::new();
        let id = det.process(IpAddr::V4(Ipv4Addr::LOCALHOST), "ua", &conn).await;
        assert!(id.signals.is_empty());
        assert_eq!(agg.len(), 1);
    }
}
