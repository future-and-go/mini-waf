use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use waf_common::config::{ApiConfig, CacheConfig, ProxyConfig, RulesConfig};

use crate::protocol::ConfigSync;

/// Subset of `AppConfig` that is safe to sync between nodes.
///
/// Excludes node-specific sections: `cluster`, `storage`, `security`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncableConfig {
    #[serde(default)]
    pub proxy: ProxyConfig,
    #[serde(default)]
    pub rules: RulesConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub api: ApiConfig,
}

/// Tracks and applies configuration synchronisation for this node.
pub struct ConfigSyncer {
    node_id: String,
    current_version: u64,
}

impl ConfigSyncer {
    pub const fn new(node_id: String) -> Self {
        Self {
            node_id,
            current_version: 0,
        }
    }

    pub const fn current_version(&self) -> u64 {
        self.current_version
    }

    /// Apply an incoming `ConfigSync` from main, updating the stored version.
    ///
    /// Returns `None` if the version is stale or payload is invalid.
    /// Returns `Some(SyncableConfig)` on success.
    pub fn apply_sync(&mut self, sync: &ConfigSync, _current_term: u64) -> Option<SyncableConfig> {
        if sync.version <= self.current_version {
            debug!(
                node_id = %self.node_id,
                local_version = self.current_version,
                incoming_version = sync.version,
                "Skipping stale ConfigSync"
            );
            return None;
        }

        match toml::from_str::<SyncableConfig>(&sync.config_toml) {
            Ok(config) => {
                debug!(
                    node_id = %self.node_id,
                    version = sync.version,
                    "Applying config sync"
                );
                self.current_version = sync.version;
                Some(config)
            }
            Err(e) => {
                warn!(
                    node_id = %self.node_id,
                    version = sync.version,
                    "Invalid config TOML in ConfigSync, keeping current: {e}"
                );
                None
            }
        }
    }

    /// Build a `ConfigSync` message from the syncable config sections.
    ///
    /// Version is a Unix timestamp in milliseconds so it is monotonically
    /// increasing across main-node restarts.  A simple counter resets to 0 on
    /// restart; workers already at version 7 would treat version 1 as stale and
    /// silently discard the new config, leaving the cluster stuck.
    pub fn build_sync(&mut self, config: &SyncableConfig) -> Result<ConfigSync> {
        let config_toml = toml::to_string(config).context("failed to serialize SyncableConfig to TOML")?;
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or_else(|_| self.current_version + 1, |d| {
                u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
            });
        // Guard against clock skew: ensure version is always strictly increasing.
        self.current_version = ts_ms.max(self.current_version + 1);
        Ok(ConfigSync {
            version: self.current_version,
            config_toml,
        })
    }
}
