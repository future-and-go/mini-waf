//! FR-025 risk store backends.
//!
//! Phase 1 ships the [`RiskStore`] trait + in-memory backend. Phase 7 adds
//! Redis backend behind `redis-store` feature flag for cluster-wide state.

pub mod memory;
pub mod store_trait;

#[cfg(feature = "redis-store")]
pub mod redis;
#[cfg(feature = "redis-store")]
pub mod redis_lua;

#[cfg(test)]
pub mod conformance;

pub use memory::MemoryRiskStore;
pub use store_trait::RiskStore;

#[cfg(feature = "redis-store")]
pub use redis::{RedisRiskConfig, RedisRiskStore};
