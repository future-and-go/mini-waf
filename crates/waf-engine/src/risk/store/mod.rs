//! FR-025 risk store backends.
//!
//! Phase 1 ships the [`RiskStore`] trait + in-memory backend. Redis backend
//! planned for Phase 7 behind a feature flag.

pub mod memory;
pub mod store_trait;

#[cfg(test)]
pub mod conformance;

pub use memory::MemoryRiskStore;
pub use store_trait::RiskStore;
