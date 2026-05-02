//! Response-cache module.
//!
//! Public surface (re-exported by `crate::lib`):
//! - [`ResponseCache`] / [`CachedResponse`] — the moka-backed store
//! - [`CacheStatsSnapshot`] — read-only counter view
//! - [`CompiledRuleSet`] / [`RuleSetHolder`] — YAML-defined per-route rules
//! - [`CacheRuleWatcher`] — `rules/cache.yaml` hot-reloader
//!
//! Internal:
//! - [`policy`] — `Verdict`, `CacheGate` trait, `CachePolicyResolver`
//! - [`gates`] — concrete gate impls (tier, method, auth, route rule,
//!   upstream Cache-Control, tier default)
//! - [`stats`] — atomic counters
//!
//! See [`policy`] for the Chain of Responsibility design rationale.

pub mod config;
pub mod gates;
pub mod policy;
pub mod rule;
pub mod rule_set;
mod stats;
mod store;
pub mod watcher;

pub use rule_set::{CompiledRuleSet, RuleSetError, RuleSetHolder};
pub use stats::CacheStatsSnapshot;
pub use store::{CachedResponse, ResponseCache};
pub use watcher::{CacheRuleWatcher, CacheWatcherError, DEFAULT_DEBOUNCE_MS, load_or_empty, reload};
