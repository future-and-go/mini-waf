//! FR-008 phase-04 — access-list evaluator (Chain of Responsibility).
//!
//! Three stages run in fixed order: Host gate → Blacklist → Whitelist. Each may
//! short-circuit; otherwise control falls through to `Continue`. The chain is a
//! hard-coded sequence rather than a `Vec<Box<dyn Stage>>` — at three stages
//! the trait indirection is pure overhead (KISS). If a fourth stage lands
//! (FR-042 Tor egress), revisit.

use std::net::IpAddr;

use waf_common::tier::Tier;

use crate::access::config::{AccessLists, WhitelistMode};

/// Default block status code. FR-002 may later thread a per-tier status
/// through `tier_policy.block_status`; for now `403` is hard-coded.
const BLOCK_STATUS: u16 = 403;

/// Outcome of evaluating an inbound request against the access lists.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AccessDecision {
    /// No access-list match; continue to subsequent WAF phases.
    Continue,
    /// Whitelist hit with `full_bypass` mode for this tier — skip later phases.
    BypassAll {
        /// Stringified client IP that matched the whitelist (for audit logging).
        matched_cidr: String,
    },
    /// Hard deny (host gate miss or blacklist hit).
    Block {
        reason: BlockReason,
        /// Stringified value that triggered the block (host or IP).
        matched: String,
        /// `true` when the snapshot was loaded with `dry_run: true`. The gateway
        /// treats dry-run blocks as `Continue` but still emits a WARN log.
        dry_run: bool,
        status: u16,
    },
}

/// Why a request was blocked at Phase 0. `'static` so audit logging is alloc-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BlockReason {
    HostGate,
    IpBlacklist,
}

impl BlockReason {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HostGate => "host_gate",
            Self::IpBlacklist => "ip_blacklist",
        }
    }
}

impl AccessDecision {
    /// Audit-log fields: `(reason, matched)`. `Continue` returns empty strings.
    #[must_use]
    #[allow(clippy::missing_const_for_fn)]
    pub fn audit_fields(&self) -> (&'static str, &str) {
        match self {
            Self::Continue => ("continue", ""),
            Self::BypassAll { matched_cidr } => ("bypass_all", matched_cidr.as_str()),
            Self::Block { reason, matched, .. } => (reason.as_str(), matched.as_str()),
        }
    }
}

/// Borrowed snapshot fed to `evaluate`. Decouples the evaluator from
/// `pingora_http::RequestHeader` so it can be unit-tested without a full
/// request mock.
#[derive(Clone, Copy, Debug)]
pub struct AccessRequestView<'a> {
    pub client_ip: IpAddr,
    pub host: &'a str,
    pub tier: Tier,
}

/// Run the three-stage chain in order: Host gate → Blacklist → Whitelist.
///
/// Order matters: a leaked whitelist IP must not bypass an explicit blacklist
/// entry, so blacklist is evaluated before whitelist.
#[must_use]
pub fn evaluate(lists: &AccessLists, view: &AccessRequestView<'_>) -> AccessDecision {
    let dry_run = lists.dry_run();

    // 1. Host gate (deny-by-default IF the per-tier list is non-empty).
    if !lists.host_gate().is_allowed(view.tier, view.host) {
        return AccessDecision::Block {
            reason: BlockReason::HostGate,
            matched: view.host.to_string(),
            dry_run,
            status: BLOCK_STATUS,
        };
    }

    // 2. Blacklist — evaluated before whitelist so explicit denies always win.
    if lists.ip_blacklist().contains(view.client_ip) {
        return AccessDecision::Block {
            reason: BlockReason::IpBlacklist,
            matched: view.client_ip.to_string(),
            dry_run,
            status: BLOCK_STATUS,
        };
    }

    // 3. Whitelist (per-tier mode dispatch).
    if lists.ip_whitelist().contains(view.client_ip) {
        return match lists.tier_mode(view.tier) {
            WhitelistMode::FullBypass => AccessDecision::BypassAll {
                matched_cidr: view.client_ip.to_string(),
            },
            WhitelistMode::BlacklistOnly => AccessDecision::Continue,
        };
    }

    AccessDecision::Continue
}

impl AccessLists {
    /// Convenience delegate so callers can write `lists.evaluate(&view)`.
    #[inline]
    #[must_use]
    pub fn evaluate(&self, view: &AccessRequestView<'_>) -> AccessDecision {
        evaluate(self, view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test ip parses")
    }

    fn view<'a>(client: &str, host: &'a str, tier: Tier) -> AccessRequestView<'a> {
        AccessRequestView {
            client_ip: ip(client),
            host,
            tier,
        }
    }

    fn lists_from(yaml: &str) -> std::sync::Arc<AccessLists> {
        AccessLists::from_yaml_str(yaml).expect("yaml parses")
    }

    #[test]
    fn t_continue_no_lists() {
        let lists = AccessLists::empty();
        let v = view("198.51.100.1", "anything", Tier::Medium);
        assert_eq!(lists.evaluate(&v), AccessDecision::Continue);
    }

    #[test]
    fn t_blacklist_v4_blocks() {
        let lists = lists_from("version: 1\nip_blacklist:\n  - 203.0.113.0/24\n");
        let v = view("203.0.113.5", "x", Tier::Medium);
        let d = lists.evaluate(&v);
        assert!(matches!(
            d,
            AccessDecision::Block {
                reason: BlockReason::IpBlacklist,
                ref matched,
                dry_run: false,
                status: 403,
            } if matched == "203.0.113.5"
        ));
    }

    #[test]
    fn t_blacklist_v6_blocks() {
        let lists = lists_from("version: 1\nip_blacklist:\n  - 2001:db8::/32\n");
        let v = view("2001:db8::1", "x", Tier::Medium);
        assert!(matches!(
            lists.evaluate(&v),
            AccessDecision::Block {
                reason: BlockReason::IpBlacklist,
                ..
            }
        ));
    }

    #[test]
    fn t_whitelist_full_bypass() {
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\ntier_whitelist_mode:\n  medium: full_bypass\n";
        let lists = lists_from(yaml);
        let v = view("10.1.2.3", "x", Tier::Medium);
        let d = lists.evaluate(&v);
        assert!(matches!(d, AccessDecision::BypassAll { ref matched_cidr } if matched_cidr == "10.1.2.3"));
    }

    #[test]
    fn t_whitelist_blacklist_only() {
        // Default mode is BlacklistOnly — whitelist hit becomes Continue, not BypassAll.
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\n";
        let lists = lists_from(yaml);
        let v = view("10.1.2.3", "x", Tier::Medium);
        assert_eq!(lists.evaluate(&v), AccessDecision::Continue);
    }

    #[test]
    fn t_blacklist_beats_whitelist() {
        // Same IP in both lists. Blacklist runs first → Block wins.
        let yaml = "version: 1\nip_whitelist:\n  - 10.0.0.0/8\nip_blacklist:\n  - 10.1.2.3\ntier_whitelist_mode:\n  medium: full_bypass\n";
        let lists = lists_from(yaml);
        let v = view("10.1.2.3", "x", Tier::Medium);
        assert!(matches!(
            lists.evaluate(&v),
            AccessDecision::Block {
                reason: BlockReason::IpBlacklist,
                ..
            }
        ));
    }

    #[test]
    fn t_host_gate_pass() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\n";
        let lists = lists_from(yaml);
        let v = view("198.51.100.1", "api.example.com", Tier::Critical);
        assert_eq!(lists.evaluate(&v), AccessDecision::Continue);
    }

    #[test]
    fn t_host_gate_block() {
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\n";
        let lists = lists_from(yaml);
        let v = view("198.51.100.1", "evil.com", Tier::Critical);
        assert!(matches!(
            lists.evaluate(&v),
            AccessDecision::Block { reason: BlockReason::HostGate, ref matched, .. } if matched == "evil.com"
        ));
    }

    #[test]
    fn t_host_gate_disabled() {
        // Medium tier has no hosts → D4 disabled-by-default → any host allowed.
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\n";
        let lists = lists_from(yaml);
        let v = view("198.51.100.1", "evil.com", Tier::Medium);
        assert_eq!(lists.evaluate(&v), AccessDecision::Continue);
    }

    #[test]
    fn t_dry_run_stamp() {
        let yaml = "version: 1\ndry_run: true\nip_blacklist:\n  - 203.0.113.5\n";
        let lists = lists_from(yaml);
        let v = view("203.0.113.5", "x", Tier::Medium);
        assert!(matches!(
            lists.evaluate(&v),
            AccessDecision::Block { dry_run: true, .. }
        ));
    }

    #[test]
    fn t_host_block_short_circuits_blacklist() {
        // Host gate must run before blacklist: even if IP is also blacklisted,
        // the reason recorded is HostGate.
        let yaml = "version: 1\nhost_whitelist:\n  critical:\n    - api.example.com\nip_blacklist:\n  - 203.0.113.5\n";
        let lists = lists_from(yaml);
        let v = view("203.0.113.5", "evil.com", Tier::Critical);
        assert!(matches!(
            lists.evaluate(&v),
            AccessDecision::Block {
                reason: BlockReason::HostGate,
                ..
            }
        ));
    }

    #[test]
    fn t_audit_fields_block() {
        let d = AccessDecision::Block {
            reason: BlockReason::IpBlacklist,
            matched: "1.2.3.4".to_string(),
            dry_run: false,
            status: 403,
        };
        assert_eq!(d.audit_fields(), ("ip_blacklist", "1.2.3.4"));
    }

    #[test]
    fn t_view_constructs_with_v4() {
        let v = AccessRequestView {
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            host: "localhost",
            tier: Tier::CatchAll,
        };
        assert_eq!(v.host, "localhost");
    }
}
