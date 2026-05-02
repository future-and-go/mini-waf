//! FR-010 phase-02 — YAML schema + parser for `configs/device-fp.yaml`.
//!
//! Pure data + validation, returns an `Arc<DeviceFpConfig>` snapshot.
//! `deny_unknown_fields` everywhere — typos in operator YAML are loud,
//! not silent. Mirrors `relay::config`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail};
use serde::Deserialize;

const SCHEMA_VERSION: u32 = 1;

/// Top-level YAML wrapper: `device_fp:` is the single root key.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFpDocument {
    #[serde(default)]
    pub device_fp: DeviceFpConfig,
}

/// Root configuration for the device-fingerprinting subsystem.
///
/// Empty file ⇒ disabled (fail-open at config layer).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceFpConfig {
    /// Schema version. Bumped only on breaking YAML changes.
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub capture: CaptureConfig,
    #[serde(default)]
    pub store: StoreConfig,
    #[serde(default)]
    pub providers: Vec<ProviderConfig>,
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
}

impl Default for DeviceFpConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            enabled: false,
            capture: CaptureConfig::default(),
            store: StoreConfig::default(),
            providers: Vec::new(),
            hot_reload: default_hot_reload(),
        }
    }
}

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}

const fn default_hot_reload() -> bool {
    true
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureConfig {
    #[serde(default)]
    pub tls: TlsCaptureConfig,
    #[serde(default)]
    pub h2: H2CaptureConfig,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsCaptureConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Subset of `["ja3", "ja4"]`. Unknown algorithms reject at validate time.
    #[serde(default)]
    pub algorithms: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct H2CaptureConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Currently only `"akamai"` is supported.
    #[serde(default = "default_h2_hash")]
    pub hash: String,
}

impl Default for H2CaptureConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hash: default_h2_hash(),
        }
    }
}

fn default_h2_hash() -> String {
    "akamai".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreConfig {
    #[serde(default = "default_backend")]
    pub backend: StoreBackend,
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u32,
    #[serde(default)]
    pub redis: Option<RedisStoreConfig>,
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            backend: StoreBackend::Memory,
            ttl_secs: default_ttl_secs(),
            redis: None,
        }
    }
}

const fn default_ttl_secs() -> u32 {
    3600
}

const fn default_backend() -> StoreBackend {
    StoreBackend::Memory
}

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StoreBackend {
    #[default]
    Memory,
    Redis,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisStoreConfig {
    pub url: String,
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,
}

fn default_redis_prefix() -> String {
    "wafp:".to_string()
}

/// One provider entry from the `providers:` array.
///
/// The `name` field selects the implementation — see
/// `registry::ProviderRegistry::from_config`. Per-provider options are
/// declared as flat optional fields here so the parser stays strict
/// (`deny_unknown_fields`); each provider only reads the fields it cares
/// about and ignores the rest.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderConfig {
    pub name: String,
    #[serde(default = "default_signal_weight")]
    pub signal_weight: u8,
    #[serde(default)]
    pub window_secs: Option<u32>,
    #[serde(default)]
    pub max_distinct_ips: Option<u16>,
    #[serde(default)]
    pub max_distinct_uas: Option<u16>,
    /// Minimum Shannon entropy * 100 (so the YAML stays integer-only).
    #[serde(default)]
    pub min_entropy_x100: Option<u16>,
    #[serde(default)]
    pub blocklist_patterns: Vec<String>,
}

const fn default_signal_weight() -> u8 {
    25
}

impl DeviceFpConfig {
    /// Parse from raw YAML text, returning a validated `Arc` snapshot.
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<Self>> {
        let doc: DeviceFpDocument = serde_yaml::from_str(s).context("device_fp: parse YAML")?;
        let cfg = doc.device_fp;
        cfg.validate()?;
        Ok(Arc::new(cfg))
    }

    /// Parse from a file path. Symlink-escape protection is the operator's
    /// responsibility (the loader watches the parent dir, so a symlink
    /// pointing outside is observable). Reject if path doesn't exist.
    pub fn from_path(path: &Path) -> anyhow::Result<Arc<Self>> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("device_fp: read {}", path.display()))?;
        Self::from_yaml_str(&raw)
    }

    /// Validate the parsed config — schema version, weight bounds, allowed
    /// algorithm names, redis URL when backend=redis.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "device_fp: unsupported schema_version {} (this build expects {})",
                self.schema_version,
                SCHEMA_VERSION
            );
        }
        for algo in &self.capture.tls.algorithms {
            match algo.as_str() {
                "ja3" | "ja4" => {}
                other => bail!("device_fp: unknown TLS algorithm {other:?} (allowed: ja3, ja4)"),
            }
        }
        match self.capture.h2.hash.as_str() {
            "akamai" => {}
            other => bail!("device_fp: unknown h2 hash {other:?} (allowed: akamai)"),
        }
        if matches!(self.store.backend, StoreBackend::Redis) && self.store.redis.is_none() {
            bail!("device_fp: store.backend=redis but store.redis missing");
        }
        let mut seen = std::collections::HashSet::new();
        for p in &self.providers {
            if !seen.insert(p.name.as_str()) {
                bail!("device_fp: duplicate provider name {:?}", p.name);
            }
            if p.signal_weight > 100 {
                bail!(
                    "device_fp: provider {:?} signal_weight={} out of range 0-100",
                    p.name,
                    p.signal_weight
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_is_disabled() {
        let cfg = DeviceFpConfig::from_yaml_str("").expect("parse empty");
        assert!(!cfg.enabled);
        assert_eq!(cfg.schema_version, SCHEMA_VERSION);
        assert!(cfg.providers.is_empty());
        assert!(cfg.hot_reload);
    }

    #[test]
    fn full_yaml_round_trip() {
        let yaml = r"
device_fp:
  enabled: true
  capture:
    tls: { enabled: true, algorithms: [ja3, ja4] }
    h2:  { enabled: true, hash: akamai }
  store:
    backend: memory
    ttl_secs: 1800
  providers:
    - name: ip_hopping
      window_secs: 600
      max_distinct_ips: 3
      signal_weight: 25
    - name: ua_entropy
      min_entropy_x100: 250
      signal_weight: 15
  hot_reload: true
";
        let cfg = DeviceFpConfig::from_yaml_str(yaml).expect("parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.providers.len(), 2);
        assert_eq!(cfg.store.ttl_secs, 1800);
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = "device_fp:\n  totally_made_up: 1\n";
        assert!(DeviceFpConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn unknown_tls_algo_rejected() {
        let yaml = "device_fp:\n  capture:\n    tls: { enabled: true, algorithms: [ja99] }\n";
        let err = DeviceFpConfig::from_yaml_str(yaml).unwrap_err();
        assert!(err.to_string().contains("unknown TLS algorithm"));
    }

    #[test]
    fn weight_out_of_range_rejected() {
        let yaml = "device_fp:\n  providers:\n    - name: p\n      signal_weight: 250\n";
        assert!(DeviceFpConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn duplicate_provider_rejected() {
        let yaml = r"
device_fp:
  providers:
    - name: ip_hopping
    - name: ip_hopping
";
        assert!(DeviceFpConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn redis_backend_requires_block() {
        let yaml = "device_fp:\n  store:\n    backend: redis\n";
        assert!(DeviceFpConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn schema_version_mismatch_rejected() {
        let yaml = "device_fp:\n  schema_version: 99\n";
        assert!(DeviceFpConfig::from_yaml_str(yaml).is_err());
    }
}
