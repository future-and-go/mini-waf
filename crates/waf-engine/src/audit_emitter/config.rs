//! Configuration for the shared audit emitter.
//!
//! Defaults are conservative: `enabled = false` ships the subsystem inert.
//! Operator must opt-in per environment via the `[audit_emitter]` TOML section.

use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

/// Default emit window in seconds — one DB row per `(client_ip, rule_id)` per
/// window.
pub const DEFAULT_WINDOW_SECS: u64 = 60;

/// Default cap on tracked bucket keys before LRU eviction kicks in.
pub const DEFAULT_MAX_KEYS: usize = 100_000;

/// Default janitor pass interval — purges expired buckets and enforces
/// `max_keys`. Matches `window_secs` so one knob covers liveness + cleanup.
pub const DEFAULT_GC_INTERVAL_SECS: u64 = 60;

/// Auto-tuned MPSC channel capacity for queued DB inserts.
///
/// Floor 512, scales with available parallelism (×256). On an 8-core CI
/// runner this yields 2048; on a 32-core production host it yields 8192.
#[must_use]
pub fn default_channel_capacity() -> usize {
    std::thread::available_parallelism()
        .map_or(8, NonZeroUsize::get)
        .saturating_mul(256)
        .max(512)
}

/// Hot-reloadable knobs for the audit emitter.
///
/// Lives behind `Arc<AuditEmitterConfig>` once handed to the emitter — the
/// emitter never mutates its own config; reload is via constructor replacement
/// at the boot site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEmitterConfig {
    /// Master kill switch. When `false`, every `emit()` short-circuits with
    /// zero allocation and zero DB / WS traffic.
    #[serde(default)]
    pub enabled: bool,

    /// Window in seconds during which a `(client_ip, rule_id)` pair emits at
    /// most one row to `security_events`. Defaults to 60s.
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,

    /// Maximum bucket keys retained in memory before LRU eviction. Cap exists
    /// purely to bound worst-case memory under hash-flood scenarios.
    #[serde(default = "default_max_keys")]
    pub max_keys: usize,

    /// MPSC channel depth between the hot path and the DB-insert worker.
    /// Defaults to `available_parallelism × 256`, floor 512.
    #[serde(default = "default_channel_capacity")]
    pub channel_capacity: usize,

    /// Janitor pass interval in seconds. Defaults to `window_secs` so the
    /// operator only has one knob to tune. Override only for tests.
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,
}

impl Default for AuditEmitterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            window_secs: DEFAULT_WINDOW_SECS,
            max_keys: DEFAULT_MAX_KEYS,
            channel_capacity: default_channel_capacity(),
            gc_interval_secs: DEFAULT_GC_INTERVAL_SECS,
        }
    }
}

const fn default_window_secs() -> u64 {
    DEFAULT_WINDOW_SECS
}

const fn default_max_keys() -> usize {
    DEFAULT_MAX_KEYS
}

const fn default_gc_interval_secs() -> u64 {
    DEFAULT_GC_INTERVAL_SECS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe_off() {
        let cfg = AuditEmitterConfig::default();
        assert!(!cfg.enabled, "must default to disabled for safety");
        assert_eq!(cfg.window_secs, 60);
        assert_eq!(cfg.max_keys, 100_000);
        assert!(cfg.channel_capacity >= 512);
    }

    #[test]
    fn channel_capacity_respects_floor() {
        let cap = default_channel_capacity();
        assert!(cap >= 512, "floor must hold even on 1-core hosts");
    }

    #[test]
    fn toml_parses_partial_config() {
        let toml_src = "enabled = true\nwindow_secs = 30";
        let cfg: AuditEmitterConfig = toml::from_str(toml_src).expect("parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.window_secs, 30);
        assert_eq!(cfg.max_keys, DEFAULT_MAX_KEYS);
    }
}
