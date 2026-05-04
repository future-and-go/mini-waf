//! FR-011 Phase 1 — minimal `BehaviorConfig` stub.
//!
//! Only the knobs Phase 1 actually uses (window size assertion, janitor TTL).
//! Full schema (per-classifier thresholds, hot-reload, etc.) lands in Phase 5.

#[derive(Clone, Copy, Debug)]
pub struct BehaviorConfig {
    /// Hard upper bound on the per-actor sample ring. Phase 1 keeps this
    /// equal to the compile-time `WINDOW=16`; the field exists so Phase 5
    /// can validate YAML-supplied values against the structural cap.
    pub window_size: u16,
    /// Idle TTL — actors whose newest sample is older than this are
    /// dropped by the janitor.
    pub actor_ttl_secs: u32,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            window_size: 16,
            actor_ttl_secs: 600,
        }
    }
}
