//! FR-025 cumulative risk scoring subsystem.
//!
//! Tracks per-actor (IP, fingerprint, session) risk state and applies a
//! threshold gate to emit Allow / Challenge / Block decisions. Mirrors the
//! FR-010 device-fingerprinting architecture: `ArcSwap<RiskConfig>` snapshot,
//! hot-reload via `notify`, and a store trait with in-memory + Redis backends.
//!
//! Module structure:
//! - [`key`]       — `RiskKey`, `SessionId`, `fp_hash` derivation
//! - [`state`]     — `RiskState`, `Contributor`, `ContributorKind`
//! - [`score`]     — pure fold function (events → updated state)
//! - [`decay`]     — pure decay with `MAX_DECAY=50` floor
//! - [`threshold`] — pure `decide(score, cfg)` → `WafAction`
//! - [`config`]    — YAML schema + `ArcSwap` hot-reload
//! - [`reload`]    — notify file watcher
//! - [`scorer`]    — Scorer orchestrator (pipeline integration)
//! - [`store`]     — `RiskStore` trait + `MemoryRiskStore` backend

pub mod anomaly;
pub mod canary;
pub mod config;
pub mod decay;
pub mod ingest;
pub mod key;
pub mod reload;
pub mod score;
pub mod scorer;
pub mod seed;
pub mod state;
pub mod store;
pub mod threshold;
pub mod velocity;

#[cfg(test)]
mod tests;

pub use anomaly::{AnomalyCtx, AnomalyLayer};
pub use canary::CanaryLayer;
pub use config::{CanaryConfig, IngestConfig, RiskConfig};
pub use ingest::{IngestMetrics, IngestMetricsSnapshot, ScoringAggregator, SignalWeights};
pub use key::{RiskKey, SessionId};
pub use reload::RiskReloader;
pub use score::{
    MAX_PER_REQUEST_DELTA, clamp_per_request_deltas, dominant_contributor, rule_delta_to_contributor,
    rule_deltas_to_contributors,
};
pub use scorer::Scorer;
pub use seed::{SeedDeltas, SeedLayer, SeedPaths, SeedReloader, SeedTables, SeedVerdict};
pub use state::{Contributor, ContributorKind, RiskState, SeedKind};
pub use store::{MemoryRiskStore, RiskStore};
#[cfg(feature = "redis-store")]
pub use store::{RedisRiskConfig, RedisRiskStore};
pub use velocity::{SequenceStore, TxEndpoint, VelocityLayer, VelocityStore};
