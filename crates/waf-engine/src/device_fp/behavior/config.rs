//! FR-011 — `BehaviorConfig` (full schema + validation, Phase 5).
//!
//! Parses the `behavior:` block of `configs/device-fp.yaml`. Field shapes
//! mirror the plan §YAML schema verbatim. Validation runs *before* the
//! atomic swap in [`crate::device_fp::reload`] so a malformed edit retains
//! the last-good config rather than corrupting live state.

use anyhow::{Result, bail};
use serde::Deserialize;

/// FR-RS-048 burst-interval classifier knobs.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BurstIntervalCfg {
    pub enabled: bool,
    /// Strict upper bound on inter-request interval (ms). Intervals
    /// equal to this value DO NOT count as bursts.
    pub threshold_ms: u64,
    /// Minimum consecutive sub-threshold intervals required to fire.
    pub min_consecutive: u16,
    /// Risk delta to emit when fired.
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
/// `cv_threshold` is the coefficient-of-variation cap (stddev/mean) — the
/// classifier fires when measured CV is *below* this value. Skip when the
/// mean interval is below `min_mean_ms` to avoid double-counting bursts.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RegularityCfg {
    pub enabled: bool,
    pub min_samples: u16,
    pub cv_threshold: f32,
    pub min_mean_ms: u64,
    pub risk_delta: u8,
}

impl Default for RegularityCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples: 6,
            cv_threshold: 0.15,
            min_mean_ms: 100,
            risk_delta: 10,
        }
    }
}

/// FR-RS-049 zero-depth classifier knobs.
///
/// Entry-page paths (`/`, `/login`, …) stay in code rather than YAML — they
/// double as recorder-time `is_entry_path` flags and changing them is a
/// schema decision, not an operator knob.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ZeroDepthCfg {
    pub enabled: bool,
    pub min_samples: u16,
    pub critical_hits_required: u16,
    pub risk_delta: u8,
    /// Not exposed in the shipped YAML (see struct doc); serde-default keeps
    /// the recorder's exempt list operator-overridable for tests.
    pub exempt_entry_paths: Vec<String>,
}

impl Default for ZeroDepthCfg {
    fn default() -> Self {
        Self {
            enabled: true,
            min_samples: 4,
            critical_hits_required: 2,
            risk_delta: 10,
            exempt_entry_paths: vec!["/".into(), "/login".into(), "/index".into()],
        }
    }
}

/// FR-011 missing-referer classifier knobs.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
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

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct BehaviorConfig {
    pub window_size: u16,
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

/// Cap mirrors `state::WINDOW`. Operators can shrink the runtime window
/// below the compile-time ring depth, but never grow past it.
const MAX_WINDOW_SIZE: u16 = 64;
const MAX_EXEMPT_LEN: usize = 256;

impl BehaviorConfig {
    /// Run the validation table from plan §Validation. On `Err`, the
    /// reload path keeps the last-good snapshot.
    pub fn validate(&self) -> Result<()> {
        let w = self.window_size;
        if !(4..=MAX_WINDOW_SIZE).contains(&w) {
            bail!("behavior.window_size {w} out of range 4..=64");
        }
        let ttl = self.actor_ttl_secs;
        if !(60..=86_400).contains(&ttl) {
            bail!("behavior.actor_ttl_secs {ttl} out of range 60..=86400");
        }

        // burst_interval
        let bi = &self.burst_interval;
        let bt = bi.threshold_ms;
        if !(1..=10_000).contains(&bt) {
            bail!("behavior.burst_interval.threshold_ms {bt} out of range 1..=10000");
        }
        let bmc = bi.min_consecutive;
        if bmc < 2 || bmc >= w {
            bail!("behavior.burst_interval.min_consecutive {bmc} out of range 2..window_size-1");
        }

        // regularity
        let r = &self.regularity;
        let rms = r.min_samples;
        if rms < 2 || rms > w {
            bail!("behavior.regularity.min_samples {rms} out of range 2..=window_size");
        }
        let cv = r.cv_threshold;
        if !(cv > 0.0 && cv <= 1.0) {
            bail!("behavior.regularity.cv_threshold {cv} out of range (0.0, 1.0]");
        }
        let rmm = r.min_mean_ms;
        if !(1..=60_000).contains(&rmm) {
            bail!("behavior.regularity.min_mean_ms {rmm} out of range 1..=60000");
        }

        // zero_depth
        let z = &self.zero_depth;
        let zms = z.min_samples;
        if zms < 2 || zms > w {
            bail!("behavior.zero_depth.min_samples {zms} out of range 2..=window_size");
        }
        let chr = z.critical_hits_required;
        if chr < 1 || chr > zms {
            bail!("behavior.zero_depth.critical_hits_required {chr} out of range 1..=min_samples");
        }

        // missing_referer exempt entries
        for p in &self.missing_referer.exempt_paths {
            check_exempt_entry("missing_referer.exempt_paths", p)?;
        }
        for p in &self.missing_referer.exempt_prefixes {
            check_exempt_entry("missing_referer.exempt_prefixes", p)?;
        }
        // risk_delta caps — u8 naturally bounded 0..=255; plan caps at 100.
        for (label, v) in [
            ("burst_interval", bi.risk_delta),
            ("regularity", r.risk_delta),
            ("zero_depth", z.risk_delta),
            ("missing_referer", self.missing_referer.risk_delta),
        ] {
            if v > 100 {
                bail!("behavior.{label}.risk_delta {v} out of range 0..=100");
            }
        }
        Ok(())
    }
}

fn check_exempt_entry(field: &str, entry: &str) -> Result<()> {
    if entry.is_empty() {
        bail!("behavior.{field} contains empty entry");
    }
    let len = entry.len();
    if len > MAX_EXEMPT_LEN {
        bail!("behavior.{field} entry exceeds {MAX_EXEMPT_LEN} chars: {len}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(yaml: &str) -> Result<BehaviorConfig> {
        let cfg: BehaviorConfig = serde_yaml::from_str(yaml)?;
        cfg.validate()?;
        Ok(cfg)
    }

    #[test]
    fn default_round_trip() {
        // Empty YAML map → all defaults; must validate.
        let cfg = parse("{}").expect("default parses + validates");
        let d = BehaviorConfig::default();
        assert_eq!(cfg.window_size, d.window_size);
        assert_eq!(cfg.actor_ttl_secs, d.actor_ttl_secs);
        assert_eq!(cfg.burst_interval.threshold_ms, d.burst_interval.threshold_ms);
        assert!((cfg.regularity.cv_threshold - d.regularity.cv_threshold).abs() < f32::EPSILON);
    }

    #[test]
    fn cv_threshold_parses_as_float() {
        // YAML "0.15" must deserialize as f32, not as a string.
        let cfg = parse("regularity:\n  cv_threshold: 0.15\n").expect("parse");
        assert!((cfg.regularity.cv_threshold - 0.15).abs() < 1e-6);
    }

    #[test]
    fn rejects_window_size_zero() {
        let err = parse("window_size: 0\n").unwrap_err();
        assert!(err.to_string().contains("window_size"));
    }

    #[test]
    fn rejects_cv_threshold_above_one() {
        let err = parse("regularity:\n  cv_threshold: 1.5\n").unwrap_err();
        assert!(err.to_string().contains("cv_threshold"));
    }

    #[test]
    fn rejects_min_consecutive_above_window() {
        // window=16, min_consecutive must be < window.
        let err = parse("burst_interval:\n  min_consecutive: 16\n").unwrap_err();
        assert!(err.to_string().contains("min_consecutive"));
    }

    #[test]
    fn rejects_empty_exempt_entry() {
        let err = parse("missing_referer:\n  exempt_paths: [\"\"]\n").unwrap_err();
        assert!(err.to_string().contains("empty entry"));
    }

    #[test]
    fn rejects_critical_hits_above_min_samples() {
        let err = parse("zero_depth:\n  min_samples: 4\n  critical_hits_required: 5\n").unwrap_err();
        assert!(err.to_string().contains("critical_hits_required"));
    }

    #[test]
    fn unknown_field_rejected() {
        let bad: Result<BehaviorConfig, _> = serde_yaml::from_str("not_a_field: 1\n");
        assert!(bad.is_err());
    }
}
