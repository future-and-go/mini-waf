//! FR-010 signal providers.
//!
//! Phase-02 ships only the [`SignalProvider`] trait + per-provider stubs.
//! Real signal-emitting logic lands in phase-06.

pub mod fp_conflict;
pub mod h2_anomaly;
pub mod ip_hopping;
pub mod ua_blocklist;
pub mod ua_entropy;

use crate::device_fp::signal::Signal;
use crate::device_fp::types::DeviceCtx;

pub use fp_conflict::FpConflictProvider;
pub use h2_anomaly::H2AnomalyProvider;
pub use ip_hopping::IpHoppingProvider;
pub use ua_blocklist::UaBlocklistProvider;
pub use ua_entropy::UaEntropyProvider;

pub trait SignalProvider: Send + Sync {
    fn name(&self) -> &'static str;
    fn evaluate(&self, ctx: &DeviceCtx<'_>) -> Vec<Signal>;
}
