use serde::{Deserialize, Serialize};

/// Community threat intelligence sharing configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityConfig {
    /// Enable community threat intelligence sharing.
    pub enabled: bool,
    /// Community server base URL (e.g. `https://community.openprx.dev`).
    #[serde(default = "default_server_url")]
    pub server_url: String,
    /// API key obtained during machine enrollment.
    /// If absent on first run, the machine will auto-enroll.
    #[serde(default)]
    pub api_key: Option<String>,
    /// Machine identifier obtained during enrollment.
    #[serde(default)]
    pub machine_id: Option<String>,
    /// Ed25519 public key (hex-encoded 32 bytes) for blocklist signature verification.
    /// When set, the WAF fetches signed+compressed snapshots from `/blocklist/full`
    /// and cryptographically verifies them before applying.
    /// When absent, falls back to the unverified `/blocklist/decoded` endpoint.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Maximum number of signals to batch before flushing.
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    /// Flush interval in seconds (flush even if batch is not full).
    #[serde(default = "default_flush_interval")]
    pub flush_interval_secs: u64,
    /// Blocklist sync interval in seconds.
    #[serde(default = "default_sync_interval")]
    pub sync_interval_secs: u64,
}

impl Default for CommunityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_url: default_server_url(),
            api_key: None,
            machine_id: None,
            public_key: None,
            batch_size: default_batch_size(),
            flush_interval_secs: default_flush_interval(),
            sync_interval_secs: default_sync_interval(),
        }
    }
}

fn default_server_url() -> String {
    "https://community.openprx.dev".to_string()
}

const fn default_batch_size() -> usize {
    50
}

const fn default_flush_interval() -> u64 {
    30
}

const fn default_sync_interval() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_match_constants() {
        let cfg = CommunityConfig::default();
        assert!(!cfg.enabled);
        assert_eq!(cfg.server_url, default_server_url());
        assert!(cfg.api_key.is_none());
        assert!(cfg.machine_id.is_none());
        assert!(cfg.public_key.is_none());
        assert_eq!(cfg.batch_size, default_batch_size());
        assert_eq!(cfg.flush_interval_secs, default_flush_interval());
        assert_eq!(cfg.sync_interval_secs, default_sync_interval());
    }

    #[test]
    fn round_trips_through_json() {
        let cfg = CommunityConfig {
            enabled: true,
            api_key: Some("k".to_string()),
            ..CommunityConfig::default()
        };
        let s = serde_json::to_string(&cfg).expect("serialize");
        let back: CommunityConfig = serde_json::from_str(&s).expect("deserialize");
        assert!(back.enabled);
        assert_eq!(back.api_key.as_deref(), Some("k"));
    }
}
