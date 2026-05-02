//! FR-004 phase-07 — YAML schema + parser for `configs/rate-limit.yaml`.
//!
//! Pure data + validation, returns an `Arc<RateLimitConfig>` runtime snapshot.
//! `deny_unknown_fields` everywhere — typos in operator YAML are loud, not
//! silent. Mirrors `device_fp::config`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use serde::Deserialize;

use waf_common::tier::Tier;

use super::RateLimitConfig;
use super::store::LimitCfg;

const SCHEMA_VERSION: u32 = 1;

/// Top-level YAML wrapper: `rate_limit:` is the single root key.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitDocument {
    #[serde(default)]
    pub rate_limit: RateLimitFileConfig,
}

/// Operator-facing YAML schema for rate-limit configuration.
///
/// Empty file ⇒ inert (no tiers limited).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitFileConfig {
    #[serde(default = "default_schema_version")]
    pub schema_version: u32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_session_cookie")]
    pub session_cookie: String,
    #[serde(default = "default_hot_reload")]
    pub hot_reload: bool,
    /// Per-tier limit configurations. Tiers omitted from the map are not
    /// rate-limited (the check skips them).
    #[serde(default)]
    pub tiers: TierMap,
    /// Optional Redis backend. Absence ⇒ memory-only standalone mode.
    #[serde(default)]
    pub redis: Option<RedisCfg>,
}

impl Default for RateLimitFileConfig {
    fn default() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            enabled: false,
            session_cookie: default_session_cookie(),
            hot_reload: default_hot_reload(),
            tiers: TierMap::default(),
            redis: None,
        }
    }
}

const fn default_schema_version() -> u32 {
    SCHEMA_VERSION
}
fn default_session_cookie() -> String {
    "SESSIONID".to_string()
}
const fn default_hot_reload() -> bool {
    true
}

/// Tier map keyed by `snake_case` names matching `Tier` variants.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierMap {
    #[serde(default)]
    pub critical: Option<TierLimitCfg>,
    #[serde(default)]
    pub high: Option<TierLimitCfg>,
    #[serde(default)]
    pub medium: Option<TierLimitCfg>,
    #[serde(default)]
    pub catch_all: Option<TierLimitCfg>,
}

/// One tier's rate-limit knobs. Mirrors `LimitCfg` 1:1.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierLimitCfg {
    pub burst_capacity: u32,
    pub burst_refill_per_s: f64,
    pub window_secs: u32,
    pub window_limit: u32,
}

/// Optional Redis backend block.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedisCfg {
    pub url: String,
    #[serde(default = "default_redis_prefix")]
    pub key_prefix: String,
    #[serde(default = "default_op_timeout_ms")]
    pub op_timeout_ms: u64,
    #[serde(default = "default_breaker_threshold")]
    pub breaker_threshold: u32,
}

fn default_redis_prefix() -> String {
    "wafrl:".to_string()
}
const fn default_op_timeout_ms() -> u64 {
    50
}
const fn default_breaker_threshold() -> u32 {
    5
}

impl RateLimitFileConfig {
    /// Parse from raw YAML text → validated runtime snapshot.
    pub fn from_yaml_str(s: &str) -> anyhow::Result<Arc<RateLimitConfig>> {
        let doc: RateLimitDocument = serde_yaml::from_str(s).context("rate_limit: parse YAML")?;
        let cfg = doc.rate_limit;
        cfg.validate()?;
        Ok(Arc::new(cfg.into_runtime()))
    }

    /// Parse from a file path.
    pub fn from_path(path: &Path) -> anyhow::Result<Arc<RateLimitConfig>> {
        let raw = std::fs::read_to_string(path).with_context(|| format!("rate_limit: read {}", path.display()))?;
        Self::from_yaml_str(&raw)
    }

    /// Schema version + range checks.
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.schema_version != SCHEMA_VERSION {
            bail!(
                "rate_limit: unsupported schema_version {} (this build expects {})",
                self.schema_version,
                SCHEMA_VERSION
            );
        }
        if self.session_cookie.is_empty() {
            bail!("rate_limit: session_cookie must not be empty");
        }
        for (name, t) in self.iter_tiers() {
            if t.burst_capacity == 0 {
                bail!("rate_limit.tiers.{name}: burst_capacity must be > 0");
            }
            if !t.burst_refill_per_s.is_finite() || t.burst_refill_per_s < 0.0 {
                bail!("rate_limit.tiers.{name}: burst_refill_per_s must be finite and >= 0");
            }
            if t.window_secs == 0 {
                bail!("rate_limit.tiers.{name}: window_secs must be > 0");
            }
            if t.window_limit == 0 {
                bail!("rate_limit.tiers.{name}: window_limit must be > 0");
            }
        }
        if let Some(r) = &self.redis
            && r.url.is_empty()
        {
            bail!("rate_limit.redis.url must not be empty when redis block is present");
        }
        Ok(())
    }

    fn iter_tiers(&self) -> impl Iterator<Item = (&'static str, &TierLimitCfg)> {
        [
            ("critical", self.tiers.critical.as_ref()),
            ("high", self.tiers.high.as_ref()),
            ("medium", self.tiers.medium.as_ref()),
            ("catch_all", self.tiers.catch_all.as_ref()),
        ]
        .into_iter()
        .filter_map(|(n, t)| t.map(|tc| (n, tc)))
    }

    /// Convert validated DTO → runtime `RateLimitConfig`.
    /// Disabled subsystem ⇒ empty tier map (check is inert).
    fn into_runtime(self) -> RateLimitConfig {
        let mut tiers: HashMap<Tier, LimitCfg> = HashMap::new();
        if self.enabled {
            if let Some(t) = self.tiers.critical {
                tiers.insert(Tier::Critical, t.into());
            }
            if let Some(t) = self.tiers.high {
                tiers.insert(Tier::High, t.into());
            }
            if let Some(t) = self.tiers.medium {
                tiers.insert(Tier::Medium, t.into());
            }
            if let Some(t) = self.tiers.catch_all {
                tiers.insert(Tier::CatchAll, t.into());
            }
        }
        RateLimitConfig {
            session_cookie: self.session_cookie,
            tiers,
        }
    }
}

impl From<TierLimitCfg> for LimitCfg {
    fn from(t: TierLimitCfg) -> Self {
        Self {
            burst_capacity: t.burst_capacity,
            burst_refill_per_s: t.burst_refill_per_s,
            window_secs: t.window_secs,
            window_limit: t.window_limit,
        }
    }
}

impl RedisCfg {
    /// Convert to the engine-side `RedisConfig`. Only meaningful when the
    /// `redis-store` feature is on; we still expose the timeout helper for
    /// non-redis builds (used by tests).
    #[must_use]
    pub const fn op_timeout(&self) -> Duration {
        Duration::from_millis(self.op_timeout_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_parses_inert() {
        let cfg = RateLimitFileConfig::from_yaml_str("").expect("empty parses");
        assert!(cfg.tiers.is_empty());
        assert_eq!(cfg.session_cookie, "SESSIONID");
    }

    #[test]
    fn full_yaml_round_trip() {
        let yaml = r#"
rate_limit:
  schema_version: 1
  enabled: true
  session_cookie: MYSID
  hot_reload: true
  tiers:
    critical:
      burst_capacity: 5
      burst_refill_per_s: 2.0
      window_secs: 60
      window_limit: 30
    catch_all:
      burst_capacity: 100
      burst_refill_per_s: 50.0
      window_secs: 60
      window_limit: 1500
  redis:
    url: "redis://127.0.0.1:6379"
    key_prefix: "wafrl:"
    op_timeout_ms: 75
    breaker_threshold: 7
"#;
        let cfg = RateLimitFileConfig::from_yaml_str(yaml).expect("parses");
        assert_eq!(cfg.session_cookie, "MYSID");
        let crit = cfg.for_tier(Tier::Critical).expect("critical");
        assert_eq!(crit.burst_capacity, 5);
        let ca = cfg.for_tier(Tier::CatchAll).expect("catch_all");
        assert_eq!(ca.window_limit, 1500);
        assert!(cfg.for_tier(Tier::High).is_none(), "high unconfigured ⇒ skipped");
    }

    #[test]
    fn redis_omitted_means_standalone() {
        let yaml = r"
rate_limit:
  enabled: true
  tiers:
    catch_all:
      burst_capacity: 10
      burst_refill_per_s: 5.0
      window_secs: 60
      window_limit: 100
";
        let cfg = RateLimitFileConfig::from_yaml_str(yaml).expect("parses");
        assert_eq!(cfg.tiers.len(), 1);
    }

    #[test]
    fn disabled_yields_empty_tiers() {
        let yaml = r"
rate_limit:
  enabled: false
  tiers:
    critical:
      burst_capacity: 5
      burst_refill_per_s: 2.0
      window_secs: 60
      window_limit: 30
";
        let cfg = RateLimitFileConfig::from_yaml_str(yaml).expect("parses");
        assert!(cfg.tiers.is_empty(), "enabled=false ⇒ inert config (no tiers)");
    }

    #[test]
    fn unknown_field_rejected() {
        let yaml = r"
rate_limit:
  enabled: true
  bogus_field: 42
";
        assert!(RateLimitFileConfig::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn schema_mismatch_rejected() {
        let yaml = r"
rate_limit:
  schema_version: 999
";
        let err = RateLimitFileConfig::from_yaml_str(yaml).unwrap_err().to_string();
        assert!(err.contains("schema_version"), "got: {err}");
    }

    #[test]
    fn zero_window_rejected() {
        let yaml = r"
rate_limit:
  enabled: true
  tiers:
    critical:
      burst_capacity: 5
      burst_refill_per_s: 2.0
      window_secs: 0
      window_limit: 30
";
        assert!(RateLimitFileConfig::from_yaml_str(yaml).is_err());
    }
}
