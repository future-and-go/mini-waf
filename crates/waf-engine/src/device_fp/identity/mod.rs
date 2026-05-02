//! FR-010 identity store backends.
//!
//! Phase-02 ships the [`IdentityStore`] trait + a no-op memory stub. The
//! real `dashmap`-backed memory impl ships in phase-05; the Redis impl
//! ships in phase-08 behind the `redis-store` feature flag.

pub mod identity_trait;
pub mod memory;

#[cfg(feature = "redis-store")]
pub mod redis;

pub use identity_trait::IdentityStore;
pub use memory::MemoryIdentityStore;
