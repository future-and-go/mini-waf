//! FR-028 Canary Honeypot layer.
//!
//! Configured canary paths (e.g., `/admin-test`, `/api-debug`) that no legitimate
//! user should hit. When triggered:
//! 1. `store.force_max()` — pins score to 100 with `pinned_until_ms`
//! 2. Adds IP to dynamic ban table (FR-005 `DynamicBanTable`)
//! 3. Returns `Block` immediately, bypassing threshold gate
//!
//! Hot-reloadable via `ArcSwap<HashSet<String>>` for path list updates.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::warn;

use crate::checks::ddos::DynamicBanTable;

/// Default canary ban TTL in seconds (1 hour).
pub const DEFAULT_CANARY_BAN_TTL_SECS: u32 = 3600;

/// Issue #60 — stable `rule_id` written to `security_events` on a honeypot
/// hit. Single source of truth so the panel filter and any historical
/// queries stay consistent across releases.
pub const HONEYPOT_RULE_ID: &str = "HONEY-001";

/// Issue #60 — human-readable rule name paired with `HONEYPOT_RULE_ID`.
pub const HONEYPOT_RULE_NAME: &str = "canary_honeypot";

/// Canary honeypot layer for scanner detection.
///
/// Maintains a hot-reloadable set of exact-match paths. Any request hitting
/// a canary path triggers immediate max-score pin and IP ban.
pub struct CanaryLayer {
    /// Hot-swappable path set. Exact-match only (case-sensitive).
    paths: ArcSwap<HashSet<String>>,
    /// Reference to `DDoS` ban table for IP blocking.
    ban_table: Option<Arc<DynamicBanTable>>,
    /// Ban TTL in seconds for canary hits.
    ban_ttl_secs: u32,
}

impl CanaryLayer {
    /// Create a new canary layer with empty paths.
    #[must_use]
    pub fn new() -> Self {
        Self {
            paths: ArcSwap::from(Arc::new(HashSet::new())),
            ban_table: None,
            ban_ttl_secs: DEFAULT_CANARY_BAN_TTL_SECS,
        }
    }

    /// Create a canary layer with initial paths.
    #[must_use]
    pub fn with_paths(paths: Vec<String>) -> Self {
        let set: HashSet<String> = paths.into_iter().collect();
        Self {
            paths: ArcSwap::from(Arc::new(set)),
            ban_table: None,
            ban_ttl_secs: DEFAULT_CANARY_BAN_TTL_SECS,
        }
    }

    /// Create a canary layer with paths and ban table reference.
    #[must_use]
    pub fn with_ban_table(paths: Vec<String>, ban_table: Arc<DynamicBanTable>, ban_ttl_secs: u32) -> Self {
        let set: HashSet<String> = paths.into_iter().collect();
        Self {
            paths: ArcSwap::from(Arc::new(set)),
            ban_table: Some(ban_table),
            ban_ttl_secs,
        }
    }

    /// Set the ban table reference.
    pub fn set_ban_table(&mut self, ban_table: Arc<DynamicBanTable>) {
        self.ban_table = Some(ban_table);
    }

    /// Set the ban TTL in seconds.
    pub const fn set_ban_ttl_secs(&mut self, ttl: u32) {
        self.ban_ttl_secs = ttl;
    }

    /// Check if the given path is a canary path (exact match).
    ///
    /// Performs O(1) hash lookup. Path must match exactly — no partial
    /// substring matching (e.g., `/admin-test/something` does NOT match
    /// `/admin-test` unless explicitly listed).
    #[inline]
    #[must_use]
    pub fn check(&self, path: &str) -> bool {
        self.paths.load().contains(path)
    }

    /// Check if path is a canary and ban the IP if so.
    ///
    /// Returns `true` if the path matched a canary (caller should block).
    /// On match:
    /// - Logs a warning (honeypot hit is a notable security event)
    /// - Adds IP to ban table with configured TTL
    pub fn check_and_ban(&self, path: &str, ip: IpAddr, now_ms: i64) -> bool {
        if !self.check(path) {
            return false;
        }

        // Log the honeypot hit
        warn!(
            canary_path = path,
            client_ip = %ip,
            ban_ttl_secs = self.ban_ttl_secs,
            "canary honeypot triggered — scanner detected"
        );

        // Add to dynamic ban table
        if let Some(ref ban_table) = self.ban_table {
            let expires_ms = now_ms.saturating_add(i64::from(self.ban_ttl_secs) * 1000);
            ban_table.insert(ip, expires_ms);
        }

        true
    }

    /// Hot-reload the path set.
    pub fn reload(&self, paths: Vec<String>) {
        let set: HashSet<String> = paths.into_iter().collect();
        self.paths.store(Arc::new(set));
    }

    /// Get the current number of canary paths.
    #[must_use]
    pub fn len(&self) -> usize {
        self.paths.load().len()
    }

    /// Check if the canary layer has no paths configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.paths.load().is_empty()
    }

    /// Get the ban TTL in seconds.
    #[must_use]
    pub const fn ban_ttl_secs(&self) -> u32 {
        self.ban_ttl_secs
    }

    /// Get the ban TTL in milliseconds.
    #[must_use]
    pub fn ban_ttl_ms(&self) -> i64 {
        i64::from(self.ban_ttl_secs) * 1000
    }
}

impl Default for CanaryLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_layer_matches_nothing() {
        let layer = CanaryLayer::new();
        assert!(!layer.check("/admin-test"));
        assert!(!layer.check("/api-debug"));
        assert!(!layer.check("/anything"));
        assert!(layer.is_empty());
    }

    #[test]
    fn exact_match_only() {
        let layer = CanaryLayer::with_paths(vec!["/admin-test".to_string(), "/api-debug".to_string()]);

        // Exact matches
        assert!(layer.check("/admin-test"));
        assert!(layer.check("/api-debug"));

        // Partial/prefix matches should NOT trigger
        assert!(!layer.check("/admin-test/"));
        assert!(!layer.check("/admin-test/something"));
        assert!(!layer.check("/api-debug/foo"));
        assert!(!layer.check("admin-test")); // missing leading slash

        // Unrelated paths
        assert!(!layer.check("/"));
        assert!(!layer.check("/admin"));
        assert!(!layer.check("/api"));
    }

    #[test]
    fn case_sensitive() {
        let layer = CanaryLayer::with_paths(vec!["/Admin-Test".to_string()]);
        assert!(layer.check("/Admin-Test"));
        assert!(!layer.check("/admin-test"));
        assert!(!layer.check("/ADMIN-TEST"));
    }

    #[test]
    fn hot_reload_updates_paths() {
        let layer = CanaryLayer::with_paths(vec!["/old-path".to_string()]);
        assert!(layer.check("/old-path"));
        assert!(!layer.check("/new-path"));

        layer.reload(vec!["/new-path".to_string(), "/another".to_string()]);

        assert!(!layer.check("/old-path"));
        assert!(layer.check("/new-path"));
        assert!(layer.check("/another"));
        assert_eq!(layer.len(), 2);
    }

    #[test]
    fn check_and_ban_adds_to_table() {
        let ban_table = Arc::new(DynamicBanTable::new());
        let layer = CanaryLayer::with_ban_table(
            vec!["/honeypot".to_string()],
            Arc::clone(&ban_table),
            3600, // 1 hour
        );

        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let now_ms = 1_000_000;

        // Should not ban for non-canary path
        assert!(!layer.check_and_ban("/normal-path", ip, now_ms));
        assert!(!ban_table.contains(ip, now_ms));

        // Should ban for canary path
        assert!(layer.check_and_ban("/honeypot", ip, now_ms));
        assert!(ban_table.contains(ip, now_ms));

        // Ban should last for TTL
        let still_banned = now_ms + 3600 * 1000 - 1;
        assert!(ban_table.contains(ip, still_banned));

        // Ban should expire after TTL
        let expired = now_ms + 3600 * 1000;
        assert!(!ban_table.contains(ip, expired));
    }

    #[test]
    fn check_without_ban_table() {
        let layer = CanaryLayer::with_paths(vec!["/trap".to_string()]);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();

        // Should still return true for canary hit, just no ban side-effect
        assert!(layer.check_and_ban("/trap", ip, 1000));
    }

    #[test]
    fn ban_ttl_configuration() {
        let mut layer = CanaryLayer::new();
        assert_eq!(layer.ban_ttl_secs(), DEFAULT_CANARY_BAN_TTL_SECS);
        assert_eq!(layer.ban_ttl_ms(), i64::from(DEFAULT_CANARY_BAN_TTL_SECS) * 1000);

        layer.set_ban_ttl_secs(7200);
        assert_eq!(layer.ban_ttl_secs(), 7200);
        assert_eq!(layer.ban_ttl_ms(), 7200 * 1000);
    }
}
