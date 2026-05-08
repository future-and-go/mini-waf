//! FR-025 risk scoring configuration.
//!
//! YAML schema for `configs/risk.yaml`. Hot-reload via `ArcSwap` + `notify`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Top-level YAML document wrapper.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskDocument {
    pub risk: RiskConfig,
}

/// Runtime risk scoring configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RiskConfig {
    /// Schema version for forward compatibility.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,

    /// Whether risk scoring is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// TTL for idle entries in seconds (default 30 min).
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u64,

    /// GC interval in seconds for purge loop.
    #[serde(default = "default_gc_interval_secs")]
    pub gc_interval_secs: u64,

    /// Session cookie name to extract `SessionId` from.
    #[serde(default)]
    pub session_cookie: Option<String>,

    /// Header name for the egress risk score (default: X-WAF-Risk-Score).
    #[serde(default = "default_header_name")]
    pub header_name: String,

    /// Whether to emit the risk score header on responses.
    #[serde(default = "default_emit_header")]
    pub emit_header: bool,

    /// Store backend configuration.
    #[serde(default)]
    pub store: StoreConfig,

    /// Decay configuration.
    #[serde(default)]
    pub decay: DecayConfig,
}

/// Store backend selection.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct StoreConfig {
    /// Backend type: "memory" or "redis" (redis requires feature flag).
    #[serde(default = "default_backend")]
    pub backend: String,
}

/// Decay behavior configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecayConfig {
    /// Minimum clean requests before decay starts.
    #[serde(default = "default_min_clean_streak")]
    pub min_clean_streak: u32,

    /// Points decayed per clean request.
    #[serde(default = "default_decay_rate")]
    pub decay_rate: u16,

    /// Floor below which automatic decay stops.
    #[serde(default = "default_max_decay")]
    pub max_decay: u32,
}

impl Default for DecayConfig {
    fn default() -> Self {
        Self {
            min_clean_streak: default_min_clean_streak(),
            decay_rate: default_decay_rate(),
            max_decay: default_max_decay(),
        }
    }
}

impl Default for RiskConfig {
    fn default() -> Self {
        Self {
            schema_version: default_schema_version(),
            enabled: default_enabled(),
            ttl_secs: default_ttl_secs(),
            gc_interval_secs: default_gc_interval_secs(),
            session_cookie: None,
            header_name: default_header_name(),
            emit_header: default_emit_header(),
            store: StoreConfig::default(),
            decay: DecayConfig::default(),
        }
    }
}

impl RiskConfig {
    /// Load config from a YAML file.
    pub fn from_path(path: &Path) -> Result<Arc<Self>> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("failed to read risk config: {}", path.display()))?;

        let doc: RiskDocument = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse risk config: {}", path.display()))?;

        Ok(Arc::new(doc.risk))
    }

    /// TTL in milliseconds.
    #[must_use]
    pub const fn ttl_ms(&self) -> i64 {
        (self.ttl_secs * 1000).cast_signed()
    }
}

const fn default_schema_version() -> u32 {
    1
}
const fn default_enabled() -> bool {
    false
}
const fn default_ttl_secs() -> u64 {
    1800 // 30 minutes
}
const fn default_gc_interval_secs() -> u64 {
    60
}
fn default_header_name() -> String {
    "X-WAF-Risk-Score".to_string()
}
const fn default_emit_header() -> bool {
    true
}
fn default_backend() -> String {
    "memory".to_string()
}
const fn default_min_clean_streak() -> u32 {
    10
}
const fn default_decay_rate() -> u16 {
    1
}
const fn default_max_decay() -> u32 {
    50
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_values() {
        let cfg = RiskConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.ttl_secs, 1800);
        assert_eq!(cfg.header_name, "X-WAF-Risk-Score");
        assert!(cfg.emit_header);
    }

    #[test]
    fn from_path_parses_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("risk.yaml");
        std::fs::write(
            &path,
            "risk:\n  enabled: true\n  ttl_secs: 3600\n  header_name: X-Risk\n",
        )
        .unwrap();

        let cfg = RiskConfig::from_path(&path).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.ttl_secs, 3600);
        assert_eq!(cfg.header_name, "X-Risk");
    }

    #[test]
    fn ttl_ms_converts_correctly() {
        let cfg = RiskConfig {
            ttl_secs: 60,
            ..Default::default()
        };
        assert_eq!(cfg.ttl_ms(), 60_000);
    }
}
