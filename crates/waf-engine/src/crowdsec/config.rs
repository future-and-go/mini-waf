use serde::{Deserialize, Serialize};

/// `CrowdSec` integration mode
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CrowdSecMode {
    /// Pull decisions from LAPI (bouncer only)
    #[default]
    Bouncer,
    /// Check requests via `AppSec` protocol
    Appsec,
    /// Both bouncer and `AppSec`
    Both,
}

/// What to do when LAPI / `AppSec` is unavailable
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FallbackAction {
    /// Allow the request (fail open)
    #[default]
    Allow,
    /// Block the request (fail closed)
    Block,
    /// Log only without blocking
    Log,
}

/// Main `CrowdSec` integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrowdSecConfig {
    /// Enable `CrowdSec` integration
    pub enabled: bool,
    /// Integration mode
    #[serde(default)]
    pub mode: CrowdSecMode,
    /// LAPI base URL (e.g. <http://localhost:8080>)
    pub lapi_url: String,
    /// Bouncer API key sent as X-Api-Key header
    pub api_key: String,
    /// Polling interval for incremental decision updates (seconds)
    #[serde(default = "default_update_frequency")]
    pub update_frequency_secs: u64,
    /// Override TTL for cached decisions (seconds, 0 = use decision duration)
    #[serde(default)]
    pub cache_ttl_secs: u64,
    /// Action when LAPI is unreachable
    #[serde(default)]
    pub fallback_action: FallbackAction,
    /// Only cache decisions whose scenario contains one of these strings (empty = all)
    #[serde(default)]
    pub scenarios_containing: Vec<String>,
    /// Exclude decisions whose scenario contains any of these strings
    #[serde(default)]
    pub scenarios_not_containing: Vec<String>,
    /// `AppSec` engine config (used when mode = appsec or both)
    pub appsec: Option<AppSecConfig>,
    /// Log pusher config (for pushing WAF events back to `CrowdSec`)
    pub pusher: Option<PusherConfig>,
}

impl Default for CrowdSecConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: CrowdSecMode::Bouncer,
            lapi_url: "http://127.0.0.1:8080".to_string(),
            api_key: String::new(),
            update_frequency_secs: default_update_frequency(),
            cache_ttl_secs: 0,
            fallback_action: FallbackAction::Allow,
            scenarios_containing: Vec::new(),
            scenarios_not_containing: Vec::new(),
            appsec: None,
            pusher: None,
        }
    }
}

/// `AppSec` protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSecConfig {
    /// `AppSec` HTTP endpoint URL
    pub endpoint: String,
    /// `AppSec` API key
    pub api_key: String,
    /// Request timeout in milliseconds
    #[serde(default = "default_appsec_timeout")]
    pub timeout_ms: u64,
    /// Action when `AppSec` is unavailable
    #[serde(default)]
    pub failure_action: FallbackAction,
    /// Number of consecutive failures before the circuit breaker opens
    #[serde(default = "default_cb_threshold")]
    pub circuit_breaker_threshold: u32,
    /// Seconds the circuit stays open before allowing a probe request
    #[serde(default = "default_cb_reset_secs")]
    pub circuit_breaker_reset_secs: u64,
}

/// Log pusher configuration (machine credentials)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PusherConfig {
    /// Machine login / `machine_id`
    pub login: String,
    /// Machine password
    pub password: String,
}

const fn default_update_frequency() -> u64 {
    10
}
const fn default_appsec_timeout() -> u64 {
    500
}
const fn default_cb_threshold() -> u32 {
    5
}
const fn default_cb_reset_secs() -> u64 {
    30
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let cfg = CrowdSecConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.mode, CrowdSecMode::Bouncer);
        assert_eq!(cfg.lapi_url, "http://127.0.0.1:8080");
        assert!(cfg.api_key.is_empty());
        assert_eq!(cfg.update_frequency_secs, default_update_frequency());
        assert_eq!(cfg.cache_ttl_secs, 0);
        assert_eq!(cfg.fallback_action, FallbackAction::Allow);
        assert!(cfg.scenarios_containing.is_empty());
        assert!(cfg.scenarios_not_containing.is_empty());
        assert!(cfg.appsec.is_none());
        assert!(cfg.pusher.is_none());
    }

    #[test]
    fn deserializes_minimal_json() {
        let raw = r#"{
            "enabled": true,
            "lapi_url": "http://example:8080",
            "api_key": "abc"
        }"#;
        let cfg: CrowdSecConfig = serde_json::from_str(raw).expect("parse");
        assert!(cfg.enabled);
        assert_eq!(cfg.lapi_url, "http://example:8080");
        assert_eq!(cfg.api_key, "abc");
        assert_eq!(cfg.mode, CrowdSecMode::Bouncer);
        assert_eq!(cfg.update_frequency_secs, default_update_frequency());
    }

    #[test]
    fn mode_and_fallback_round_trip() {
        let modes = [CrowdSecMode::Bouncer, CrowdSecMode::Appsec, CrowdSecMode::Both];
        for m in modes {
            let s = serde_json::to_string(&m).expect("ser");
            let back: CrowdSecMode = serde_json::from_str(&s).expect("de");
            assert_eq!(m, back);
        }
        let actions = [FallbackAction::Allow, FallbackAction::Block, FallbackAction::Log];
        for a in actions {
            let s = serde_json::to_string(&a).expect("ser");
            let back: FallbackAction = serde_json::from_str(&s).expect("de");
            assert_eq!(a, back);
        }
    }

    #[test]
    fn appsec_config_circuit_breaker_defaults_from_json() {
        let raw = r#"{
            "endpoint": "http://localhost:7422",
            "api_key": "test-key"
        }"#;
        let cfg: AppSecConfig = serde_json::from_str(raw).expect("parse");
        assert_eq!(cfg.circuit_breaker_threshold, 5);
        assert_eq!(cfg.circuit_breaker_reset_secs, 30);
        assert_eq!(cfg.timeout_ms, 500);
    }
}
