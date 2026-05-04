//! FR-011 — `BehaviorConfig` (Phase 1 + per-classifier knobs).
//!
//! Phase 1 introduced window-size + TTL. Phase 3 added the first classifier
//! sub-config (`burst_interval`). Phase 4 adds three more (`regularity`,
//! `zero_depth`, `missing_referer`). Full YAML schema + hot-reload lands
//! in Phase 5; for now, classifier sub-structs live here so providers can
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

/// FR-011 regularity (CV-based bot cadence) knobs.
///
/// Fires when the trailing `min_samples` intervals have a coefficient of
/// variation (stddev/mean) below `max_cv_x1000 / 1000`. Skip when the
/// mean interval is below `min_mean_ms` — sub-burst-threshold cadences
/// are owned by `burst_interval`, not regularity.
#[derive(Clone, Copy, Debug)]
pub struct RegularityCfg {
    pub enabled: bool,
    pub min_samples: u16,
    pub min_mean_ms: u64,
    /// Coefficient-of-variation cap, scaled ×1000 (e.g. 150 == 0.15).
    pub max_cv_x1000: u32,
    pub risk_delta: u8,
}

impl Default for RegularityCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples: 6,
            min_mean_ms: 100,
            max_cv_x1000: 150,
            risk_delta: 10,
        }
    }
}

/// FR-RS-049 zero-depth classifier knobs.
///
/// Fires when an actor has hammered exactly one path on a Critical-tier
/// resource without ever sending a Referer. Entry-page paths (e.g.
/// `/login`) are exempted because they are legitimately zero-depth.
#[derive(Clone, Debug)]
pub struct ZeroDepthCfg {
    pub enabled: bool,
    pub min_samples: u16,
    pub min_critical_samples: u16,
    pub risk_delta: u8,
    /// Paths that count as legitimate zero-depth landings — when the only
    /// observed path is in this list, the classifier stays silent.
    pub exempt_entry_paths: Vec<String>,
}

impl Default for ZeroDepthCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples: 4,
            min_critical_samples: 2,
            risk_delta: 10,
            exempt_entry_paths: vec!["/".into(), "/login".into(), "/index".into()],
        }
    }
}

/// FR-011 missing-referer classifier knobs.
///
/// Fires the first time an unidentified actor hits a non-exempt path
/// without sending a Referer header (and without the `Sec-Purpose:
/// prefetch` hint that legitimately suppresses Referer in browsers).
#[derive(Clone, Debug)]
pub struct MissingRefererCfg {
    pub enabled: bool,
    pub risk_delta: u8,
    pub exempt_paths: Vec<String>,
    pub exempt_prefixes: Vec<String>,
}

impl Default for MissingRefererCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            risk_delta: 5,
            exempt_paths: vec!["/".into(), "/login".into(), "/index".into(), "/health".into()],
            exempt_prefixes: vec!["/static/".into(), "/assets/".into(), "/api/".into()],
        }
    }
}

#[derive(Clone, Debug)]
pub struct BehaviorConfig {
    /// Hard upper bound on the per-actor sample ring. Phase 1 keeps this
    /// equal to the compile-time `WINDOW=16`; the field exists so Phase 5
    /// can validate YAML-supplied values against the structural cap.
    pub window_size: u16,
    /// Idle TTL — actors whose newest sample is older than this are
    /// dropped by the janitor.
    pub actor_ttl_secs: u32,
    pub burst_interval: BurstIntervalCfg,
    pub regularity: RegularityCfg,
    pub zero_depth: ZeroDepthCfg,
    pub missing_referer: MissingRefererCfg,
}

impl Default for BehaviorConfig {
    fn default() -> Self {
        Self {
            window_size: 16,
            actor_ttl_secs: 600,
            burst_interval: BurstIntervalCfg::default(),
            regularity: RegularityCfg::default(),
            zero_depth: ZeroDepthCfg::default(),
            missing_referer: MissingRefererCfg::default(),
        }
    }
}
