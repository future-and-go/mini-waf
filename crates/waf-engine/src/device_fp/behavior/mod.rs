//! FR-011 — behavioral anomaly detection.
//!
//! Phase 1: per-actor sliding-window state + `Recorder` data layer.
//! Classifiers (rate, burst, scan, repetition) wire in Phase 2+.

pub mod config;
pub mod providers;
pub mod recorder;
pub mod state;

pub use config::{BehaviorConfig, BurstIntervalCfg};
pub use providers::BurstIntervalProvider;
pub use recorder::{ActorBehaviorSnapshot, Recorder};
