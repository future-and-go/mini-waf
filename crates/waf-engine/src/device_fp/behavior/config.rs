//! FR-011 — `BehaviorConfig` (Phase 1 + per-classifier knobs).
//!
//! Phase 1 introduced window-size + TTL. Phase 3 adds the first classifier
//! sub-config (`burst_interval`). Full YAML schema + hot-reload lands in
//! Phase 5; for now, classifier sub-structs live here so providers can
//! `cfg.load()` and read their own slice without coordinating across types.

/// FR-RS-048 burst-interval classifier knobs.
///
/// Defaults match the requirement: ≥5 consecutive intervals < 50 ms → +15 risk.
#[derive(Clone, Copy, Debug)]
pub struct BurstIntervalCfg {
    pub enabled: bool,
    /// Strict upper bound on inter-request interval (ms). Intervals
    /// exactly equal to this value DO NOT count as bursts.
    pub threshold_ms: u64,
    /// Minimum consecutive sub-threshold intervals required to fire.
    pub min_consecutive: u16,
    /// Risk delta to emit when fired. `u8` cap prevents config-injected
    /// score overflow downstream (see plan §Security).
    pub risk_delta: u8,
}

impl Default for BurstIntervalCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            threshold_ms: 50,
            min_consecutive: 5,
            risk_delta: 15,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BehaviorConfig {
    /// Hard upper bound on the per-actor sample ring. Phase 1 keeps this
    /// equal to the compile-time `WINDOW=16`; the field exists so Phase 5
    /// can validate YAML-supplied values against the structural cap.
    pub window_size: u16,
    /// Idle TTL — actors whose newest sample is older than this are
    /// dropped by the janitor.
    pub actor_ttl_secs: u32,
    /// FR-RS-048 burst-interval classifier knobs.
    pub burst_interval: BurstIntervalCfg,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            window_size: 16,
            actor_ttl_secs: 600,
            burst_interval: BurstIntervalCfg::default(),
        }
    }
}
