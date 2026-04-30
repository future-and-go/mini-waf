//! FR-008 phase-05 — Phase-0 access-list gate.
//!
//! Wraps the hot-swappable `AccessLists` snapshot and translates the
//! engine-level [`AccessDecision`] into a gateway-level [`AccessGateOutcome`]
//! the proxy can act on (`Continue`, `Bypass`, `Block(status)`).
//!
//! The gate is invoked directly from [`crate::proxy::WafProxy::request_filter`]
//! — *not* registered in [`crate::pipeline::RequestFilterChain`] — because that
//! chain runs in `upstream_request_filter` (post-WAF) and Phase 0 must
//! short-circuit before the WAF engine pays cost.

use std::net::IpAddr;
use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_common::tier::Tier;
use waf_engine::access::{AccessDecision, AccessLists, AccessRequestView, BlockReason};

/// Outcome the proxy acts on after Phase-0 evaluation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessGateOutcome {
    /// No match (or dry-run block) — proceed to WAF engine.
    Continue,
    /// Whitelist hit with `full_bypass` — skip the WAF engine for this request.
    Bypass,
    /// Hard deny — render an error page with this status (typically 403).
    Block(u16),
}

/// Phase-0 access-list gate over a hot-swappable [`AccessLists`] snapshot.
///
/// Optional on [`crate::proxy::WafProxy`]: when absent every request is
/// `Continue` (mirrors the boot fallback used by `tier_registry`).
pub struct AccessPhaseGate {
    lists: Arc<ArcSwap<AccessLists>>,
}

impl AccessPhaseGate {
    #[must_use]
    pub const fn new(lists: Arc<ArcSwap<AccessLists>>) -> Self {
        Self { lists }
    }

    /// Evaluate against the live snapshot. Audit logs are emitted here so the
    /// proxy keeps a single responsibility (writing the response).
    pub fn evaluate(&self, host: &str, peer_ip: IpAddr, tier: Tier) -> AccessGateOutcome {
        let lists = self.lists.load_full();
        let view = AccessRequestView {
            client_ip: peer_ip,
            host,
            tier,
        };
        translate(lists.evaluate(&view))
    }
}

/// Pure side-effect-free decision → outcome map. Tests target this directly so
/// they don't need to spin up an `ArcSwap`.
fn translate(decision: AccessDecision) -> AccessGateOutcome {
    match decision {
        AccessDecision::Continue => AccessGateOutcome::Continue,
        AccessDecision::BypassAll { matched_cidr } => {
            // Audit on every bypass — D6 compliance: must NOT skip audit log.
            tracing::info!(
                access_decision = "bypass_all",
                matched = %matched_cidr,
                "access: whitelist full-bypass"
            );
            AccessGateOutcome::Bypass
        }
        AccessDecision::Block {
            reason,
            matched,
            dry_run,
            status,
        } => {
            let reason_str = match reason {
                BlockReason::HostGate => "host_gate",
                BlockReason::IpBlacklist => "ip_blacklist",
            };
            if dry_run {
                tracing::warn!(
                    access_decision = "dry_run_block",
                    access_reason = reason_str,
                    matched = %matched,
                    status,
                    "access: would block (dry-run)"
                );
                AccessGateOutcome::Continue
            } else {
                tracing::warn!(
                    access_decision = "block",
                    access_reason = reason_str,
                    matched = %matched,
                    status,
                    "access: block"
                );
                AccessGateOutcome::Block(status)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip")
    }

    #[test]
    fn translate_continue_passes_through() {
        assert_eq!(translate(AccessDecision::Continue), AccessGateOutcome::Continue);
    }

    #[test]
    fn translate_bypass_all() {
        let d = AccessDecision::BypassAll {
            matched_cidr: "10.0.0.1".into(),
        };
        assert_eq!(translate(d), AccessGateOutcome::Bypass);
    }

    #[test]
    fn translate_block_returns_status() {
        let d = AccessDecision::Block {
            reason: BlockReason::IpBlacklist,
            matched: "203.0.113.5".into(),
            dry_run: false,
            status: 403,
        };
        assert_eq!(translate(d), AccessGateOutcome::Block(403));
    }

    #[test]
    fn translate_dry_run_block_continues() {
        let d = AccessDecision::Block {
            reason: BlockReason::HostGate,
            matched: "evil.com".into(),
            dry_run: true,
            status: 403,
        };
        assert_eq!(translate(d), AccessGateOutcome::Continue);
    }

    #[test]
    fn gate_evaluate_empty_lists_continues() {
        let lists = AccessLists::empty();
        let gate = AccessPhaseGate::new(Arc::new(ArcSwap::from(lists)));
        let outcome = gate.evaluate("any", IpAddr::V4(Ipv4Addr::LOCALHOST), Tier::CatchAll);
        assert_eq!(outcome, AccessGateOutcome::Continue);
    }

    #[test]
    fn gate_evaluate_blacklist_blocks() {
        let lists = AccessLists::from_yaml_str("version: 1\nip_blacklist:\n  - 203.0.113.0/24\n").expect("yaml");
        let gate = AccessPhaseGate::new(Arc::new(ArcSwap::from(lists)));
        assert_eq!(gate.evaluate("h", ip("203.0.113.5"), Tier::Medium), AccessGateOutcome::Block(403));
    }

    #[test]
    fn gate_evaluate_whitelist_full_bypass() {
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\ntier_whitelist_mode:\n  medium: full_bypass\n";
        let lists = AccessLists::from_yaml_str(yaml).expect("yaml");
        let gate = AccessPhaseGate::new(Arc::new(ArcSwap::from(lists)));
        assert_eq!(gate.evaluate("h", ip("10.1.2.3"), Tier::Medium), AccessGateOutcome::Bypass);
    }

    #[test]
    fn gate_evaluate_host_gate_blocks() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\n";
        let lists = AccessLists::from_yaml_str(yaml).expect("yaml");
        let gate = AccessPhaseGate::new(Arc::new(ArcSwap::from(lists)));
        assert_eq!(
            gate.evaluate("evil.com", ip("198.51.100.1"), Tier::Critical),
            AccessGateOutcome::Block(403)
        );
    }

    #[test]
    fn gate_evaluate_dry_run_block_continues() {
        let yaml = "version: 1\ndry_run: true\nip_blacklist:\n  - 203.0.113.5\n";
        let lists = AccessLists::from_yaml_str(yaml).expect("yaml");
        let gate = AccessPhaseGate::new(Arc::new(ArcSwap::from(lists)));
        assert_eq!(
            gate.evaluate("h", ip("203.0.113.5"), Tier::Medium),
            AccessGateOutcome::Continue
        );
    }

    #[test]
    fn gate_hot_swap_picks_up_new_snapshot() {
        // Phase-06 will wire a file watcher to this swap; verify the read path
        // already sees swap-in-place.
        let initial = AccessLists::empty();
        let swap = Arc::new(ArcSwap::from(initial));
        let gate = AccessPhaseGate::new(Arc::clone(&swap));
        assert_eq!(
            gate.evaluate("h", ip("203.0.113.5"), Tier::Medium),
            AccessGateOutcome::Continue
        );

        let next = AccessLists::from_yaml_str("version: 1\nip_blacklist:\n  - 203.0.113.5\n").expect("yaml");
        swap.store(next);
        assert_eq!(
            gate.evaluate("h", ip("203.0.113.5"), Tier::Medium),
            AccessGateOutcome::Block(403)
        );
    }
}
