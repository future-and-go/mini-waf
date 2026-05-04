//! FR-011 — behavioral anomaly detection.
//!
//! Phase 1: per-actor sliding-window state + `Recorder` data layer.
//! Phase 3: `BurstIntervalProvider`.
//! Phase 4: `RegularityProvider`, `ZeroDepthProvider`, `MissingRefererProvider`.

pub mod config;
pub(crate) mod path_classifier;
pub mod providers;
pub mod recorder;
pub mod state;

pub use config::{BehaviorConfig, BurstIntervalCfg, MissingRefererCfg, RegularityCfg, ZeroDepthCfg};
pub use providers::{BurstIntervalProvider, MissingRefererProvider, RegularityProvider, ZeroDepthProvider};
pub use recorder::{ActorBehaviorSnapshot, Recorder};
