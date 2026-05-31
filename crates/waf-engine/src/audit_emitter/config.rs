//! `TOML`-deserialised configuration for the audit emitter.
//!
//! All knobs except `enabled` and `window_secs` are construction-time only
//! (changing them requires a restart). Hot-reload is supported for `enabled`
//! and `window_secs` via `ArcSwap`; construction-time knob changes are logged
//! as warnings.
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::thread;

use serde::{Deserialize, Serialize};

/// Minimum permitted `channel_capacity`. Values below this floor are silently
/// raised to prevent unbounded `QueueFullDropped` storms under modest load.
pub const CHANNEL_CAPACITY_FLOOR: usize = 4096;

/// Default token-bucket depth for the global per-`rule_id` rate limiter.
pub const DEFAULT_GLOBAL_TOKENS_PER_SEC: u32 = 100;

const fn default_enabled() -> bool {
    false
}

const fn default_window_secs() -> u64 {
    60
}

const fn default_channel_capacity() -> usize {
    0 // 0 → auto: available_parallelism * 64, floored at CHANNEL_CAPACITY_FLOOR
}

const fn default_gc_interval_secs() -> u64 {
    30
}

const fn default_max_keys() -> usize {
    10_000
}

const fn default_global_tokens_per_sec() -> u32 {
    DEFAULT_GLOBAL_TOKENS_PER_SEC
}

/// Per-`rule_id` global token-bucket rate overrides.
///
/// Keys must match the built-in `rule_id` grammar (`^[A-Z]+-[A-Z]+-\d{3}$`).
/// Values are tokens per second. Unrecognised keys are ignored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalRateConfig {
    #[serde(flatten)]
    pub overrides: HashMap<String, u32>,
}

/// Full audit-emitter configuration (`TOML` section `[audit_emitter]`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEmitterConfig {
    /// Master on/off switch. Default `false` — no overhead when disabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Per-(`client_ip`, `rule_id`) rate-limit window in seconds.
    /// Hot-reloadable via `ArcSwap`.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Bounded mpsc channel capacity for the DB insert worker.
    /// `0` means auto-size: `available_parallelism * 64`, floored at
    /// `CHANNEL_CAPACITY_FLOOR`.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,

    /// Janitor GC tick interval in seconds.
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,

    /// Maximum number of `(client_ip, rule_id)` bucket entries before
    /// LRU eviction triggers.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,

    /// Default global tokens/s for all built-in `rule_id` values.
    #[serde(default = "default_global_tokens_per_sec")]
    pub global_tokens_per_sec: u32,

    /// Per-`rule_id` overrides for the global token bucket.
    #[serde(default)]
    pub global_rate: GlobalRateConfig,
}

impl Default for AuditEmitterConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            window_secs: default_window_secs(),
            channel_capacity: default_channel_capacity(),
            gc_interval_secs: default_gc_interval_secs(),
            max_keys: default_max_keys(),
            global_tokens_per_sec: default_global_tokens_per_sec(),
            global_rate: GlobalRateConfig::default(),
        }
    }
}

/// Fallback parallelism when `available_parallelism` itself errors — picks
/// a conservative 4-thread default. `NonZeroUsize::new(4)` is `Some` because
/// 4 is non-zero, so this `unwrap_or` line is dead-code on every platform.
const FALLBACK_PARALLELISM: NonZeroUsize = match NonZeroUsize::new(4) {
    Some(v) => v,
    None => NonZeroUsize::MIN,
};

impl AuditEmitterConfig {
    /// Resolve the actual channel capacity, applying the floor.
    pub fn resolved_channel_capacity(&self) -> usize {
        let raw = if self.channel_capacity == 0 {
            let parallelism = thread::available_parallelism().unwrap_or(FALLBACK_PARALLELISM).get();
            parallelism * 64
        } else {
            self.channel_capacity
        };
        raw.max(CHANNEL_CAPACITY_FLOOR)
    }

    /// Returns the global token rate for a specific `rule_id` (per-rule override
    /// or default).
    pub fn tokens_per_sec_for(&self, rule_id: &str) -> u32 {
        self.global_rate
            .overrides
            .get(rule_id)
            .copied()
            .unwrap_or(self.global_tokens_per_sec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_disabled() {
        assert!(!AuditEmitterConfig::default().enabled);
    }

    #[test]
    fn channel_capacity_floor_applied() {
        let cfg = AuditEmitterConfig {
            channel_capacity: 0,
            ..Default::default()
        };
        assert!(cfg.resolved_channel_capacity() >= CHANNEL_CAPACITY_FLOOR);
    }

    #[test]
    fn channel_capacity_explicit_below_floor_raised() {
        let cfg = AuditEmitterConfig {
            channel_capacity: 1,
            ..Default::default()
        };
        assert_eq!(cfg.resolved_channel_capacity(), CHANNEL_CAPACITY_FLOOR);
    }

    #[test]
    fn channel_capacity_explicit_above_floor_kept() {
        let cfg = AuditEmitterConfig {
            channel_capacity: 99_999,
            ..Default::default()
        };
        assert_eq!(cfg.resolved_channel_capacity(), 99_999);
    }

    #[test]
    fn per_rule_override_takes_effect() {
        let mut cfg = AuditEmitterConfig::default();
        cfg.global_rate.overrides.insert("BOT-XFF-001".into(), 200);
        assert_eq!(cfg.tokens_per_sec_for("BOT-XFF-001"), 200);
        assert_eq!(cfg.tokens_per_sec_for("BOT-TOR-001"), DEFAULT_GLOBAL_TOKENS_PER_SEC);
    }

    #[test]
    fn toml_roundtrip() {
        let toml = r#"
enabled = true
window_secs = 30
channel_capacity = 8192
gc_interval_secs = 60
max_keys = 5000
global_tokens_per_sec = 50

[global_rate]
"BOT-XFF-001" = 200
"TX-SEQ-001"  = 150
"#;
        let cfg: AuditEmitterConfig = toml::from_str(toml).expect("valid toml");
        assert!(cfg.enabled);
        assert_eq!(cfg.window_secs, 30);
        assert_eq!(cfg.resolved_channel_capacity(), 8192);
        assert_eq!(cfg.tokens_per_sec_for("BOT-XFF-001"), 200);
        assert_eq!(cfg.tokens_per_sec_for("TX-SEQ-001"), 150);
        assert_eq!(cfg.tokens_per_sec_for("TX-LIMIT-001"), 50);
    }
}
