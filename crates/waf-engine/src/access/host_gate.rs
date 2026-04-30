//! Per-tier `Host` header allowlist (FR-008 phase-03).
//!
//! Strict exact-match gate. Empty list for a tier = disabled (D4 safety rail):
//! `is_allowed` returns true unconditionally so a missing config never locks a
//! tenant out. Lookups are case-insensitive (RFC 6125 §6.4.1) and a defensive
//! port strip handles `Host: example.com:8443` even though the parser rejects
//! port suffixes at insert time.

use std::collections::HashSet;

use waf_common::tier::Tier;

/// O(1) per-tier exact-match Host allowlist. Wildcards are intentionally out of
/// scope for phase-1 (D2/D3); add a separate suffix matcher if needed later.
///
/// Per-tier sets are named fields rather than `[HashSet; 4]` to satisfy
/// `clippy::indexing-slicing` without `unsafe` — the compiler proves
/// exhaustiveness on `Tier`.
#[derive(Debug, Default)]
pub struct HostGate {
    critical: HashSet<String>,
    high: HashSet<String>,
    medium: HashSet<String>,
    catch_all: HashSet<String>,
}

impl HostGate {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a host into a tier's allowlist. Trims surrounding whitespace and
    /// lowercases ASCII so lookup normalization always matches insertion.
    pub fn insert(&mut self, tier: Tier, host: &str) {
        self.set_mut(tier).insert(host.trim().to_ascii_lowercase());
    }

    /// `true` when the request's `Host` header is allowed for this tier, OR the
    /// tier list is empty (D4 disabled-by-default).
    #[inline]
    #[must_use]
    pub fn is_allowed(&self, tier: Tier, host_header: &str) -> bool {
        let set = self.set(tier);
        if set.is_empty() {
            return true;
        }
        // Strip first `:` defensively — `Host: example.com:8443` is valid HTTP.
        let h = host_header.split(':').next().unwrap_or(host_header);
        set.contains(&h.trim().to_ascii_lowercase())
    }

    /// `true` when no hosts are configured for this tier — phase-04 audit log
    /// records `gate=disabled` so operators can see the D4 path was taken.
    #[inline]
    #[must_use]
    pub fn is_disabled_for(&self, tier: Tier) -> bool {
        self.set(tier).is_empty()
    }

    #[inline]
    const fn set(&self, tier: Tier) -> &HashSet<String> {
        match tier {
            Tier::Critical => &self.critical,
            Tier::High => &self.high,
            Tier::Medium => &self.medium,
            Tier::CatchAll => &self.catch_all,
        }
    }

    #[inline]
    const fn set_mut(&mut self, tier: Tier) -> &mut HashSet<String> {
        match tier {
            Tier::Critical => &mut self.critical,
            Tier::High => &mut self.high,
            Tier::Medium => &mut self.medium,
            Tier::CatchAll => &mut self.catch_all,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_empty_disabled() {
        let g = HostGate::new();
        assert!(g.is_disabled_for(Tier::Critical));
        assert!(g.is_allowed(Tier::Critical, "anything.example.com"));
    }

    #[test]
    fn t_strict_hit() {
        let mut g = HostGate::new();
        g.insert(Tier::Critical, "api.example.com");
        assert!(g.is_allowed(Tier::Critical, "api.example.com"));
    }

    #[test]
    fn t_strict_miss() {
        let mut g = HostGate::new();
        g.insert(Tier::Critical, "api.example.com");
        assert!(!g.is_allowed(Tier::Critical, "evil.com"));
    }

    #[test]
    fn t_case_insensitive() {
        let mut g = HostGate::new();
        g.insert(Tier::Critical, "Api.Example.com");
        assert!(g.is_allowed(Tier::Critical, "API.example.COM"));
    }

    #[test]
    fn t_port_stripped() {
        let mut g = HostGate::new();
        g.insert(Tier::Critical, "api.example.com");
        assert!(g.is_allowed(Tier::Critical, "api.example.com:8443"));
    }

    #[test]
    fn t_per_tier_isolation() {
        let mut g = HostGate::new();
        g.insert(Tier::Critical, "api.example.com");
        // Medium tier left empty → D4: any host allowed.
        assert!(g.is_allowed(Tier::Medium, "evil.com"));
        // But Critical still strict.
        assert!(!g.is_allowed(Tier::Critical, "evil.com"));
    }
}
