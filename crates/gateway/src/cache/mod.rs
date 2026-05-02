//! Response-cache module.
//!
//! Public surface (re-exported by `crate::lib`):
//! - [`ResponseCache`] / [`CachedResponse`] — the moka-backed store
//! - [`CacheStatsSnapshot`] — read-only counter view
//!
//! Internal:
//! - [`policy`] — `Verdict`, `CacheGate` trait, `CachePolicyResolver`
//! - [`gates`] — concrete gate impls (tier, method, upstream Cache-Control,
//!   tier default)
//! - [`stats`] — atomic counters
//!
//! See [`policy`] for the Chain of Responsibility design rationale.

pub mod gates;
pub mod policy;
mod stats;
mod store;

pub use stats::CacheStatsSnapshot;
pub use store::{CachedResponse, ResponseCache};
