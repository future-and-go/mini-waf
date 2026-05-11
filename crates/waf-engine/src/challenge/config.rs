//! FR-006 challenge engine configuration.
//!
//! YAML schema for `configs/challenge.yaml`. Hot-reload via `ArcSwap` + `notify`.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::challenge::pow::{DifficultyMap, DifficultyTier};

/// Top-level YAML document wrapper.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeDocument {
    pub challenge: ChallengeConfig,
}

/// Runtime challenge engine configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChallengeConfig {
    /// Whether challenge engine is enabled.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Challenge type: `js_challenge` (only supported type currently).
    #[serde(default = "default_challenge_type", rename = "type")]
    pub challenge_type: String,

    /// `PoW` difficulty settings.
    #[serde(default)]
    pub difficulty: DifficultyConfig,

    /// Token/cookie settings.
    #[serde(default)]
    pub token: TokenConfig,

    /// Branding for challenge page.
    #[serde(default)]
    pub branding: BrandingConfig,

    /// Nonce store settings.
    #[serde(default)]
    pub nonce_store: NonceStoreConfig,
}

/// `PoW` difficulty configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DifficultyConfig {
    /// Default difficulty (leading zero bits).
    #[serde(default = "default_difficulty")]
    pub default: u8,

    /// Risk-based difficulty tiers.
    #[serde(default)]
    pub tiers: Vec<DifficultyTierConfig>,
}

/// A single difficulty tier mapping risk range to difficulty.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DifficultyTierConfig {
    pub min_risk: u8,
    pub max_risk: u8,
    pub difficulty: u8,
}

/// Token/cookie configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenConfig {
    /// Token TTL in seconds.
    #[serde(default = "default_ttl_secs")]
    pub ttl_secs: u32,

    /// Cookie name for challenge token.
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,

    /// Cookie max-age in seconds.
    #[serde(default = "default_cookie_max_age")]
    pub cookie_max_age: u32,

    /// `SameSite` attribute: `Strict`, `Lax`, or `None`.
    #[serde(default = "default_same_site")]
    pub same_site: String,

    /// `HttpOnly` flag. Must be false for JS to read the redirect URL.
    #[serde(default)]
    pub http_only: bool,
}

/// Branding configuration for challenge page.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrandingConfig {
    /// Page title.
    #[serde(default = "default_title")]
    pub title: String,

    /// Message shown to users during challenge.
    #[serde(default = "default_message")]
    pub message: String,
}

/// Nonce store configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NonceStoreConfig {
    /// Maximum capacity for consumed nonces.
    #[serde(default = "default_capacity")]
    pub capacity: usize,
}

// === Default implementations ===

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            challenge_type: default_challenge_type(),
            difficulty: DifficultyConfig::default(),
            token: TokenConfig::default(),
            branding: BrandingConfig::default(),
            nonce_store: NonceStoreConfig::default(),
        }
    }
}

impl Default for DifficultyConfig {
    fn default() -> Self {
        Self {
            default: default_difficulty(),
            tiers: vec![
                DifficultyTierConfig {
                    min_risk: 30,
                    max_risk: 40,
                    difficulty: 14,
                },
                DifficultyTierConfig {
                    min_risk: 40,
                    max_risk: 55,
                    difficulty: 16,
                },
                DifficultyTierConfig {
                    min_risk: 55,
                    max_risk: 70,
                    difficulty: 18,
                },
            ],
        }
    }
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            ttl_secs: default_ttl_secs(),
            cookie_name: default_cookie_name(),
            cookie_max_age: default_cookie_max_age(),
            same_site: default_same_site(),
            http_only: false,
        }
    }
}

impl Default for BrandingConfig {
    fn default() -> Self {
        Self {
            title: default_title(),
            message: default_message(),
        }
    }
}

impl Default for NonceStoreConfig {
    fn default() -> Self {
        Self {
            capacity: default_capacity(),
        }
    }
}

// === Default value functions ===

const fn default_enabled() -> bool {
    true
}

fn default_challenge_type() -> String {
    "js_challenge".to_string()
}

const fn default_difficulty() -> u8 {
    16
}

const fn default_ttl_secs() -> u32 {
    300
}

fn default_cookie_name() -> String {
    "__waf_cc".to_string()
}

const fn default_cookie_max_age() -> u32 {
    300
}

fn default_same_site() -> String {
    "Strict".to_string()
}

fn default_title() -> String {
    "Security Check".to_string()
}

fn default_message() -> String {
    "Please wait while we verify your browser...".to_string()
}

const fn default_capacity() -> usize {
    100_000
}

// === Conversions ===

impl From<&DifficultyConfig> for DifficultyMap {
    fn from(cfg: &DifficultyConfig) -> Self {
        Self {
            default: cfg.default,
            tiers: cfg
                .tiers
                .iter()
                .map(|t| DifficultyTier {
                    min_risk: t.min_risk,
                    max_risk: t.max_risk,
                    difficulty: t.difficulty,
                })
                .collect(),
        }
    }
}

impl ChallengeConfig {
    /// Load config from a YAML file.
    pub fn from_path(path: &Path) -> Result<Arc<Self>> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read challenge config: {}", path.display()))?;

        let doc: ChallengeDocument = serde_yaml::from_str(&content)
            .with_context(|| format!("failed to parse challenge config: {}", path.display()))?;

        Ok(Arc::new(doc.challenge))
    }

    /// Convert difficulty config to runtime `DifficultyMap`.
    #[must_use]
    pub fn to_difficulty_map(&self) -> DifficultyMap {
        DifficultyMap::from(&self.difficulty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_config_values() {
        let cfg = ChallengeConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.challenge_type, "js_challenge");
        assert_eq!(cfg.difficulty.default, 16);
        assert_eq!(cfg.token.ttl_secs, 300);
        assert_eq!(cfg.token.cookie_name, "__waf_cc");
    }

    #[test]
    fn from_path_parses_yaml() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("challenge.yaml");
        std::fs::write(&path, "challenge:\n  enabled: false\n  type: js_challenge\n").unwrap();

        let cfg = ChallengeConfig::from_path(&path).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.challenge_type, "js_challenge");
    }

    #[test]
    fn difficulty_config_converts_to_map() {
        let cfg = ChallengeConfig::default();
        let map = cfg.to_difficulty_map();
        assert_eq!(map.default, 16);
        assert_eq!(map.tiers.len(), 3);
        assert_eq!(map.difficulty_for_risk(35), 14);
        assert_eq!(map.difficulty_for_risk(50), 16);
    }

    #[test]
    fn token_config_defaults() {
        let cfg = TokenConfig::default();
        assert_eq!(cfg.ttl_secs, 300);
        assert_eq!(cfg.cookie_name, "__waf_cc");
        assert_eq!(cfg.same_site, "Strict");
        assert!(!cfg.http_only);
    }
}
