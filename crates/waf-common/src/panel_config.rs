//! Runtime panel configuration persisted as `waf-panel.toml`.
//!
//! Editable via the admin API (`/api/panel-config`) or directly on disk.
//! The proxy reads these fields opportunistically as engine features land;
//! until then values are stored faithfully for operator workflows.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Reference to the panel TOML path inside the main `AppConfig`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PanelFileRef {
    /// Relative to the main config file directory, or absolute.
    #[serde(default)]
    pub config_path: Option<String>,
}

/// Top-level document stored in `waf-panel.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WafPanelConfig {
    #[serde(default)]
    pub shadow_mode: bool,

    /// Maximum score treated as allow band (must be `< risk_challenge`).
    #[serde(default = "default_risk_allow")]
    pub risk_allow: u32,
    #[serde(default = "default_risk_challenge")]
    pub risk_challenge: u32,
    /// Minimum score for block (must be `> risk_challenge`).
    #[serde(default = "default_risk_block")]
    pub risk_block: u32,

    #[serde(default = "default_challenge_type")]
    pub challenge_type: String,

    #[serde(default = "default_honeypot_paths")]
    pub honeypot_paths: Vec<String>,

    #[serde(default)]
    pub response_filtering: ResponseFilteringPanel,

    #[serde(default)]
    pub trusted_waf_bypass: TrustedBypassPanel,

    #[serde(default)]
    pub rate_limits: RateLimitsPanel,

    #[serde(default)]
    pub auto_block: AutoBlockPanel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResponseFilteringPanel {
    #[serde(default = "default_true")]
    pub block_stack_traces: bool,
    #[serde(default = "default_json_redact_fields")]
    pub json_redact_fields: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TrustedBypassPanel {
    #[serde(default = "default_trusted_cidrs")]
    pub cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitsPanel {
    #[serde(default = "default_rps")]
    pub default_rps: u32,
    #[serde(default = "default_burst")]
    pub burst: u32,
    #[serde(default = "default_session_expiry")]
    pub session_expiry_secs: u64,
    #[serde(default)]
    pub global_rps: u32,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default)]
    pub fail_open: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AutoBlockPanel {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_auto_min_events")]
    pub min_events: u32,
    #[serde(default = "default_auto_window_secs")]
    pub window_secs: u64,
}

#[derive(Debug, Error)]
pub enum PanelConfigError {
    #[error("risk thresholds require risk_allow < risk_challenge < risk_block")]
    RiskOrdering,
    #[error("invalid trusted CIDR {0:?}: {1}")]
    BadCidr(String, String),
    #[error("honeypot path must start with '/'")]
    HoneypotPath,
    #[error("JSON redact field must match /^[a-zA-Z_][a-zA-Z0-9_]*$/")]
    RedactField,
}

impl Default for WafPanelConfig {
    fn default() -> Self {
        Self {
            shadow_mode: false,
            risk_allow: default_risk_allow(),
            risk_challenge: default_risk_challenge(),
            risk_block: default_risk_block(),
            challenge_type: default_challenge_type(),
            honeypot_paths: default_honeypot_paths(),
            response_filtering: ResponseFilteringPanel::default(),
            trusted_waf_bypass: TrustedBypassPanel::default(),
            rate_limits: RateLimitsPanel::default(),
            auto_block: AutoBlockPanel::default(),
        }
    }
}

impl Default for TrustedBypassPanel {
    fn default() -> Self {
        Self {
            cidrs: default_trusted_cidrs(),
        }
    }
}

impl Default for RateLimitsPanel {
    fn default() -> Self {
        Self {
            default_rps: default_rps(),
            burst: default_burst(),
            session_expiry_secs: default_session_expiry(),
            global_rps: 0,
            request_timeout_secs: default_request_timeout(),
            fail_open: false,
        }
    }
}

impl Default for AutoBlockPanel {
    fn default() -> Self {
        Self {
            enabled: false,
            min_events: default_auto_min_events(),
            window_secs: default_auto_window_secs(),
        }
    }
}

const fn default_true() -> bool {
    true
}

const fn default_risk_allow() -> u32 {
    51
}

const fn default_risk_challenge() -> u32 {
    74
}

const fn default_risk_block() -> u32 {
    75
}

fn default_challenge_type() -> String {
    "js_challenge".to_string()
}

fn default_honeypot_paths() -> Vec<String> {
    vec![
        "/.env".to_string(),
        "/.git/config".to_string(),
        "/wp-admin/install.php".to_string(),
        "/phpmyadmin".to_string(),
        "/.aws/credentials".to_string(),
        "/actuator/env".to_string(),
    ]
}

fn default_json_redact_fields() -> Vec<String> {
    vec![
        "password".to_string(),
        "token".to_string(),
        "secret".to_string(),
        "api_key".to_string(),
    ]
}

fn default_trusted_cidrs() -> Vec<String> {
    vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
}

const fn default_rps() -> u32 {
    100
}

const fn default_burst() -> u32 {
    200
}

const fn default_session_expiry() -> u64 {
    3600
}

const fn default_request_timeout() -> u64 {
    30
}

const fn default_auto_min_events() -> u32 {
    5
}

const fn default_auto_window_secs() -> u64 {
    60
}

impl Default for ResponseFilteringPanel {
    fn default() -> Self {
        Self {
            block_stack_traces: true,
            json_redact_fields: default_json_redact_fields(),
        }
    }
}

impl WafPanelConfig {
    /// Validate operator-supplied values (also run after deserializing from disk).
    pub fn validate(&self) -> Result<(), PanelConfigError> {
        if !(self.risk_allow < self.risk_challenge && self.risk_challenge < self.risk_block) {
            return Err(PanelConfigError::RiskOrdering);
        }

        for c in &self.trusted_waf_bypass.cidrs {
            Self::parse_cidr(c)?;
        }

        for p in &self.honeypot_paths {
            if !p.starts_with('/') {
                return Err(PanelConfigError::HoneypotPath);
            }
        }

        for f in &self.response_filtering.json_redact_fields {
            if !is_safe_json_field_name(f) {
                return Err(PanelConfigError::RedactField);
            }
        }

        Ok(())
    }

    fn parse_cidr(raw: &str) -> Result<(), PanelConfigError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(PanelConfigError::BadCidr(raw.to_string(), "empty".into()));
        }
        if s.parse::<std::net::IpAddr>().is_ok() {
            return Ok(());
        }
        s.parse::<ipnet::IpNet>()
            .map_err(|e| PanelConfigError::BadCidr(s.to_string(), e.to_string()))?;
        Ok(())
    }

    /// Load from UTF-8 TOML bytes.
    pub fn from_toml_str(raw: &str) -> Result<Self, anyhow::Error> {
        let c: Self = toml::from_str(raw)?;
        c.validate()?;
        Ok(c)
    }

    /// Serialize to TOML for atomic writes.
    pub fn to_toml_string(&self) -> Result<String, anyhow::Error> {
        Ok(toml::to_string_pretty(self)?)
    }
}

fn is_safe_json_field_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Load panel config from disk, or `Ok(None)` if path missing (caller may create default).
pub fn load_panel_config(path: &Path) -> anyhow::Result<Option<WafPanelConfig>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)?;
    Ok(Some(WafPanelConfig::from_toml_str(&raw)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_round_trip_toml() {
        let d = WafPanelConfig::default();
        let toml = d.to_toml_string().expect("serialize");
        let back = WafPanelConfig::from_toml_str(&toml).expect("parse");
        assert_eq!(d, back);
    }

    #[test]
    fn rejects_bad_risk_order() {
        let c = WafPanelConfig {
            risk_allow: 80,
            ..Default::default()
        };
        assert!(matches!(c.validate(), Err(PanelConfigError::RiskOrdering)));
    }
}
