//! FR-025 Phase 4 — Async ingest pipeline.
//!
//! Replaces `NoopAggregator` with `ScoringAggregator` — bounded MPSC channel +
//! worker that translates `Signal` → `Contributor`, builds `RiskKey` from
//! fingerprint hash, and calls `store.apply`.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    try_send     ┌──────────────┐    apply    ┌───────────┐
//! │ RiskAggregator  │ ──────────────► │    Worker    │ ──────────► │ RiskStore │
//! │ (submit)        │   bounded ch    │  (async)     │             │           │
//! └─────────────────┘                 └──────────────┘             └───────────┘
//!         │                                  │
//!         │ drop-with-warn                   │ Signal → Contributor
//!         ▼                                  ▼
//!    IngestMetrics                      SignalWeights
//! ```
//!
//! ## Semantics
//!
//! - `submit` is fire-and-forget: never blocks, drops with warning on overflow.
//! - Bounded channel (default 65536) prevents unbounded memory growth.
//! - Worker is supervised: panics trigger restart with exponential backoff.
//! - Signals map to contributors via configurable `SignalWeights`.
//! - Async path uses `fp_hash` only; sync path handles IP-based scoring.
//!
//! ## Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use waf_engine::risk::ingest::{ScoringAggregator, SignalWeights};
//! use waf_engine::risk::store::MemoryRiskStore;
//!
//! let store = Arc::new(MemoryRiskStore::new());
//! let (aggregator, worker_handle) = ScoringAggregator::start(store, SignalWeights::default());
//!
//! // Wire aggregator into DeviceFpDetector
//! let detector = DeviceFpDetector::empty().with_aggregator(Arc::new(aggregator));
//!
//! // On shutdown, drop aggregator to close channel
//! drop(aggregator);
//! let _ = worker_handle.await;
//! ```

mod aggregator_impl;
mod metrics;
mod signal_to_contributor;
mod worker;

pub use aggregator_impl::{DEFAULT_CHANNEL_CAPACITY, ScoringAggregator};
pub use metrics::{IngestMetrics, IngestMetricsSnapshot};
pub use signal_to_contributor::{SignalWeights, signal_to_contributor, signals_to_contributors};
pub use worker::Job;
