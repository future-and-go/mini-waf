//! FR-008 Phase-0 access-list gate — gateway bridge.
//!
//! # Why inline, not in `RequestFilterChain`?
//!
//! `RequestFilterChain` runs inside `upstream_request_filter`, which fires
//! *after* `upstream_peer` has already established the TCP connection to the
//! backend. Blocking at that point wastes a backend slot.  This gate runs
//! inside `request_filter` — the very first Pingora callback — so a blacklisted
//! IP is rejected before any upstream work begins (D6).
//!
//! # Concurrency model
//!
//! `AccessPhaseGate` holds an `Arc<ArcSwap<AccessLists>>`. Every `evaluate`
//! call does a single `ArcSwap::load` (one atomic read) to get a snapshot; no
//! mutex is held across the evaluation. The hot-reload watcher (Phase 07)
//! swaps the inner `Arc<AccessLists>` without touching this struct.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use tracing::{info, warn};
use waf_common::tier::Tier;
use waf_engine::access::{AccessDecision, AccessLists, AccessRequestView};

/// Gateway-level outcome after the Phase-0 access gate runs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessGateOutcome {
    /// No access-list match; continue to WAF engine.
    Continue,
    /// Whitelist `full_bypass` hit; skip WAF engine and body inspection.
    Bypass,
    /// Hard deny. Carry the HTTP status code to use in the error response.
    Block(u16),
}

/// Wraps the hot-swappable `AccessLists` snapshot and exposes a single
/// `evaluate` method that translates engine-level `AccessDecision` into the
/// gateway-level `AccessGateOutcome`.
pub struct AccessPhaseGate {
    pub lists: Arc<ArcSwap<AccessLists>>,
}

impl AccessPhaseGate {
    /// Construct a gate backed by `lists`. The `ArcSwap` may be swapped at any
    /// time by the file-watcher; `evaluate` always reads the current snapshot.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn new(lists: Arc<ArcSwap<AccessLists>>) -> Self {
        Self { lists }
    }

    /// Evaluate `(host, peer_ip, tier)` against the current access-list
    /// snapshot and return a gateway outcome.
    ///
    /// - `Continue` → fall through to `engine.inspect()`.
    /// - `Bypass`   → skip engine; set `ctx.access_bypass = true`.
    /// - `Block(s)` → render error page with status `s` and terminate.
    ///
    /// `dry_run = true` blocks are treated as `Continue` but emit a WARN log.
    #[must_use]
    pub fn evaluate(&self, host: &str, peer_ip: IpAddr, tier: Tier) -> AccessGateOutcome {
        let snapshot = self.lists.load();
        let view = AccessRequestView {
            client_ip: peer_ip,
            host,
            tier,
        };
        match snapshot.evaluate(&view) {
            AccessDecision::Continue => AccessGateOutcome::Continue,
            AccessDecision::BypassAll { matched_cidr } => {
                info!(
                    matched = %matched_cidr,
                    %host,
                    ?tier,
                    "access: whitelist bypass"
                );
                AccessGateOutcome::Bypass
            }
            AccessDecision::Block {
                reason,
                matched,
                dry_run,
                status,
            } => {
                if dry_run {
                    warn!(
                        reason = reason.as_str(),
                        matched = %matched,
                        dry_run = true,
                        %status,
                        %host,
                        ?tier,
                        "access: block (dry-run) — treating as continue"
                    );
                    AccessGateOutcome::Continue
                } else {
                    warn!(
                        reason = reason.as_str(),
                        matched = %matched,
                        %status,
                        %host,
                        ?tier,
                        "access: block"
                    );
                    AccessGateOutcome::Block(status)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use arc_swap::ArcSwap;
    use std::sync::Arc;
    use waf_engine::access::AccessLists;

    fn gate_from(yaml: &str) -> AccessPhaseGate {
        let lists = AccessLists::from_yaml_str(yaml).expect("valid yaml");
        AccessPhaseGate::new(Arc::new(ArcSwap::new(lists)))
    }

    fn gate_empty() -> AccessPhaseGate {
        let lists = AccessLists::empty();
        AccessPhaseGate::new(Arc::new(ArcSwap::new(lists)))
    }

    fn ipv4(s: &str) -> IpAddr {
        s.parse().expect("valid ip")
    }

    // 1. Continue when lists are empty (gate present, nothing configured).
    #[test]
    fn continue_when_lists_empty() {
        let gate = gate_empty();
        let outcome = gate.evaluate("example.com", ipv4("1.2.3.4"), Tier::Medium);
        assert_eq!(outcome, AccessGateOutcome::Continue);
    }

    // 2. Continue when no blacklist / whitelist match.
    #[test]
    fn continue_when_no_match() {
        let gate = gate_from("version: 1\nip_blacklist:\n  - 10.0.0.0/8\n");
        let outcome = gate.evaluate("example.com", ipv4("192.168.1.1"), Tier::Medium);
        assert_eq!(outcome, AccessGateOutcome::Continue);
    }

    // 3. Bypass when whitelist full_bypass matches.
    #[test]
    fn bypass_when_whitelist_full_bypass_match() {
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\ntier_whitelist_mode:\n  medium: full_bypass\n";
        let gate = gate_from(yaml);
        let outcome = gate.evaluate("example.com", ipv4("10.1.2.3"), Tier::Medium);
        assert_eq!(outcome, AccessGateOutcome::Bypass);
    }

    // 4. Continue when whitelist mode is blacklist_only (default).
    #[test]
    fn continue_when_whitelist_blacklist_only_match() {
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\n";
        let gate = gate_from(yaml);
        let outcome = gate.evaluate("example.com", ipv4("10.1.2.3"), Tier::Medium);
        assert_eq!(outcome, AccessGateOutcome::Continue);
    }

    // 5. Block when blacklist matches.
    #[test]
    fn block_when_blacklist_match() {
        let gate = gate_from("version: 1\nip_blacklist:\n  - 203.0.113.0/24\n");
        let outcome = gate.evaluate("example.com", ipv4("203.0.113.5"), Tier::Medium);
        assert!(matches!(outcome, AccessGateOutcome::Block(403)));
    }

    // 6. Block when host gate denies (host not in per-tier allowlist).
    #[test]
    fn block_when_host_gate_mismatch() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\n";
        let gate = gate_from(yaml);
        // "evil.com" is not in the Critical tier host list → block.
        let outcome = gate.evaluate("evil.com", ipv4("1.2.3.4"), Tier::Critical);
        assert!(matches!(outcome, AccessGateOutcome::Block(_)));
    }

    // 7. Dry-run block returns Continue (not Block).
    #[test]
    fn dry_run_block_returns_continue() {
        let yaml = "version: 1\ndry_run: true\nip_blacklist:\n  - 203.0.113.5\n";
        let gate = gate_from(yaml);
        let outcome = gate.evaluate("example.com", ipv4("203.0.113.5"), Tier::Medium);
        // Dry-run must NOT block; gateway must continue to WAF engine.
        assert_eq!(outcome, AccessGateOutcome::Continue);
    }

    // 8. Blacklist beats whitelist (blacklist evaluated first).
    #[test]
    fn blacklist_beats_whitelist() {
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\nip_blacklist:\n  - 10.1.2.3\ntier_whitelist_mode:\n  medium: full_bypass\n";
        let gate = gate_from(yaml);
        // Same IP in both — blacklist wins.
        let outcome = gate.evaluate("example.com", ipv4("10.1.2.3"), Tier::Medium);
        assert!(matches!(outcome, AccessGateOutcome::Block(_)));
    }

    // 9. Host gate disabled for tiers with no host list → Continue.
    #[test]
    fn host_gate_disabled_when_tier_has_no_list() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\n";
        let gate = gate_from(yaml);
        // Medium tier has no host list → gate is disabled for Medium → Continue.
        let outcome = gate.evaluate("evil.com", ipv4("1.2.3.4"), Tier::Medium);
        assert_eq!(outcome, AccessGateOutcome::Continue);
    }
}
