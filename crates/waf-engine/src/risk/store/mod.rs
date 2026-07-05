//! Risk store backends.
//!
//! The [`RiskStore`] trait has an in-memory backend, plus a Redis backend
//! behind the `redis-store` feature flag for cluster-wide state.

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
