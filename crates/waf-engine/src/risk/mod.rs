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

pub mod config;
pub mod decay;
pub mod key;
pub mod reload;
pub mod score;
pub mod scorer;
pub mod state;
pub mod store;
pub mod threshold;

pub use config::RiskConfig;
pub use key::{RiskKey, SessionId};
pub use reload::RiskReloader;
pub use scorer::Scorer;
pub use state::{Contributor, ContributorKind, RiskState};
pub use store::{MemoryRiskStore, RiskStore};
