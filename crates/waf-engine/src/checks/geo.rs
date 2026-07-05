//! GeoIP-based access control check.
//!
//! Evaluates country/region rules against the geo information that was
//! already populated by `GeoIpService` before the checker pipeline runs.
//!
//! Rules support two modes:
//! - **blocklist** – block requests from specific countries / ISO codes
//! - **allowlist** – only allow requests from specific countries / ISO codes
//!   (all others are blocked)
//!
//! Rules are loaded per-host via [`GeoCheck::load_rules`].

use std::collections::HashSet;
use std::sync::Arc;

use dashmap::DashMap;
use waf_common::{DetectionResult, Phase, RequestCtx};

use super::Check;

/// A single geo-based rule.
#[derive(Debug, Clone)]
pub struct GeoRule {
    pub id: String,
    pub name: String,
    pub mode: GeoRuleMode,
    /// ISO country codes to match (uppercase, e.g. "CN", "US").
    pub iso_codes: HashSet<String>,
    /// Country names to match (case-insensitive).
    pub countries: HashSet<String>,
    /// `AllowOnly` only: block when the request has no determinable country
    /// (missing xdb / lookup failure / private IP). Default `false` =
    /// fail-open. Ignored for `Block` rules.
    pub fail_closed: bool,
}

/// Whether the rule blocks the listed countries or allows only them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GeoRuleMode {
    /// Block requests from these countries.
    Block,
    /// Allow requests only from these countries; block everything else.
    AllowOnly,
}

/// Host-level geo rule set.
#[derive(Debug, Default)]
struct HostGeoRules {
    rules: Vec<GeoRule>,
}

/// GeoIP-based access control check.
///
/// Thread-safe: rules are stored in a `DashMap` keyed by host code.
pub struct GeoCheck {
    /// Rules per host code. Key `"*"` holds global rules.
    rules: Arc<DashMap<String, HostGeoRules>>,
}

impl GeoCheck {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(DashMap::new()),
        }
    }

    /// Replace all geo rules for the given host (or `"*"` for global rules).
    ///
    /// ISO codes are uppercased here, at load time, so the per-request match
    /// in `geo_matches` can compare without allocating (`GeoIpInfo.iso_code`
    /// is uppercased at parse time).
    pub fn load_rules(&self, host_code: &str, mut rules: Vec<GeoRule>) {
        for rule in &mut rules {
            rule.iso_codes = std::mem::take(&mut rule.iso_codes)
                .into_iter()
                .map(|mut code| {
                    code.make_ascii_uppercase();
                    code
                })
                .collect();
        }
        self.rules.insert(host_code.to_string(), HostGeoRules { rules });
    }

    /// Remove all rules for a host.
    pub fn clear_rules(&self, host_code: &str) {
        self.rules.remove(host_code);
    }

    /// Host codes that currently have rules loaded. Used by the file loader
    /// to clear hosts that disappear between two loads.
    pub fn loaded_hosts(&self) -> Vec<String> {
        self.rules.iter().map(|entry| entry.key().clone()).collect()
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn eval_rules(&self, host_code: &str, geo: &waf_common::GeoIpInfo) -> Option<DetectionResult> {
        // Host-specific rules first
        if let Some(entry) = self.rules.get(host_code)
            && let Some(r) = Self::match_rules(geo, &entry.rules)
        {
            return Some(r);
        }
        // Global rules
        if let Some(entry) = self.rules.get("*")
            && let Some(r) = Self::match_rules(geo, &entry.rules)
        {
            return Some(r);
        }
        None
    }

    fn eval_fail_closed(&self, host_code: &str) -> Option<DetectionResult> {
        // Host-specific rules first
        if let Some(entry) = self.rules.get(host_code)
            && let Some(r) = Self::match_fail_closed(&entry.rules)
        {
            return Some(r);
        }
        // Global rules
        if let Some(entry) = self.rules.get("*")
            && let Some(r) = Self::match_fail_closed(&entry.rules)
        {
            return Some(r);
        }
        None
    }

    /// With no determinable country only a fail-closed `AllowOnly` rule can
    /// act; `Block` rules cannot match a specific country without data.
    fn match_fail_closed(rules: &[GeoRule]) -> Option<DetectionResult> {
        rules
            .iter()
            .find(|rule| rule.mode == GeoRuleMode::AllowOnly && rule.fail_closed)
            .map(|rule| DetectionResult {
                rule_id: Some(rule.id.clone()),
                rule_name: rule.name.clone(),
                phase: Phase::GeoIp,
                detail: format!(
                    "Blocked by geo allowlist '{}': geo data unavailable (fail-closed)",
                    rule.name
                ),
                rule_action: None,
                action_status: None,
            })
    }

    fn match_rules(geo: &waf_common::GeoIpInfo, rules: &[GeoRule]) -> Option<DetectionResult> {
        for rule in rules {
            let matched = Self::geo_matches(geo, rule);
            match rule.mode {
                GeoRuleMode::Block => {
                    if matched {
                        return Some(DetectionResult {
                            rule_id: Some(rule.id.clone()),
                            rule_name: rule.name.clone(),
                            phase: Phase::GeoIp,
                            detail: format!(
                                "Blocked by geo rule '{}': country='{}' iso='{}'",
                                rule.name, geo.country, geo.iso_code
                            ),
                            rule_action: None,
                            action_status: None,
                        });
                    }
                }
                GeoRuleMode::AllowOnly => {
                    if !matched && (!geo.country.is_empty() || !geo.iso_code.is_empty()) {
                        return Some(DetectionResult {
                            rule_id: Some(rule.id.clone()),
                            rule_name: rule.name.clone(),
                            phase: Phase::GeoIp,
                            detail: format!(
                                "Blocked by geo allowlist '{}': country='{}' iso='{}' not in allowed list",
                                rule.name, geo.country, geo.iso_code
                            ),
                            rule_action: None,
                            action_status: None,
                        });
                    }
                }
            }
        }
        None
    }

    /// Returns `true` if the geo info matches any of the rule's criteria.
    fn geo_matches(geo: &waf_common::GeoIpInfo, rule: &GeoRule) -> bool {
        // Match ISO code — both sides are uppercased ahead of time (rules at
        // load, geo at parse), so this compare is allocation-free.
        if !geo.iso_code.is_empty() && rule.iso_codes.contains(&geo.iso_code) {
            return true;
        }
        // Match country name (case-insensitive)
        if !geo.country.is_empty() && rule.countries.iter().any(|c| c.eq_ignore_ascii_case(&geo.country)) {
            return true;
        }
        false
    }
}

impl Default for GeoCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for GeoCheck {
    fn check(&self, ctx: &mut RequestCtx) -> Option<DetectionResult> {
        match &ctx.geo {
            // Data present — unchanged matching path.
            Some(geo) if !(geo.country.is_empty() && geo.iso_code.is_empty()) => {
                self.eval_rules(&ctx.host_config.code, geo)
            }
            // Geo absent or empty (service disabled, missing xdb, lookup
            // failure, private IP): fail-open unless a fail-closed AllowOnly
            // rule applies to this host.
            _ => self.eval_fail_closed(&ctx.host_config.code),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::{GeoIpInfo, HostConfig, RequestCtx};

    fn make_ctx(iso: &str, country: &str) -> RequestCtx {
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
            peer_ip: "1.2.3.4".parse::<IpAddr>().unwrap(),
            client_port: 12345,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: Some(GeoIpInfo {
                country: country.to_string(),
                iso_code: iso.to_string(),
                ..Default::default()
            }),
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        }
    }

    #[test]
    fn block_by_iso() {
        let check = GeoCheck::new();
        check.load_rules(
            "*",
            vec![GeoRule {
                id: "GEO-001".into(),
                name: "Block KP".into(),
                mode: GeoRuleMode::Block,
                iso_codes: ["KP".to_string()].into(),
                countries: HashSet::new(),
                fail_closed: false,
            }],
        );

        let mut ctx = make_ctx("KP", "North Korea");
        assert!(check.check(&mut ctx).is_some());

        let mut ctx2 = make_ctx("US", "United States");
        assert!(check.check(&mut ctx2).is_none());
    }

    #[test]
    fn lowercase_rule_iso_codes_match() {
        let check = GeoCheck::new();
        check.load_rules(
            "*",
            vec![GeoRule {
                id: "GEO-003".into(),
                name: "Block CN".into(),
                mode: GeoRuleMode::Block,
                iso_codes: ["cn".to_string()].into(),
                countries: HashSet::new(),
                fail_closed: false,
            }],
        );

        let mut ctx = make_ctx("CN", "China");
        assert!(
            check.check(&mut ctx).is_some(),
            "lowercase rule ISO code must match after load-time normalization"
        );
    }

    fn allow_only_us_rule(fail_closed: bool) -> GeoRule {
        GeoRule {
            id: "GEO-ALLOW".into(),
            name: "Allow US".into(),
            mode: GeoRuleMode::AllowOnly,
            iso_codes: ["US".to_string()].into(),
            countries: HashSet::new(),
            fail_closed,
        }
    }

    #[test]
    fn allow_only_fail_closed_blocks_when_geo_is_none() {
        let check = GeoCheck::new();
        check.load_rules("*", vec![allow_only_us_rule(true)]);

        let mut ctx = make_ctx("", "");
        ctx.geo = None;
        let result = check.check(&mut ctx).expect("fail-closed allowlist must block");
        assert_eq!(result.phase, Phase::GeoIp);
        assert_eq!(result.rule_id.as_deref(), Some("GEO-ALLOW"));
        assert!(result.detail.contains("geo data unavailable"));
    }

    #[test]
    fn allow_only_fail_closed_blocks_when_geo_is_empty() {
        let check = GeoCheck::new();
        check.load_rules("*", vec![allow_only_us_rule(true)]);

        // Empty GeoIpInfo — private IP / lookup miss.
        let mut ctx = make_ctx("", "");
        assert!(check.check(&mut ctx).is_some());
    }

    #[test]
    fn allow_only_fail_open_passes_when_geo_unavailable() {
        let check = GeoCheck::new();
        check.load_rules("*", vec![allow_only_us_rule(false)]);

        let mut empty = make_ctx("", "");
        assert!(check.check(&mut empty).is_none(), "fail-open on empty geo is unchanged");

        let mut none = make_ctx("", "");
        none.geo = None;
        assert!(check.check(&mut none).is_none(), "fail-open on absent geo is unchanged");
    }

    #[test]
    fn allow_only_fail_closed_with_geo_data_matches_as_before() {
        let check = GeoCheck::new();
        check.load_rules("*", vec![allow_only_us_rule(true)]);

        let mut allowed = make_ctx("US", "United States");
        assert!(check.check(&mut allowed).is_none(), "listed country passes");

        let mut blocked = make_ctx("CN", "China");
        assert!(check.check(&mut blocked).is_some(), "unlisted country still blocked");
    }

    #[test]
    fn block_rule_never_fails_closed() {
        let check = GeoCheck::new();
        check.load_rules(
            "*",
            vec![GeoRule {
                id: "GEO-BLOCK".into(),
                name: "Block KP".into(),
                mode: GeoRuleMode::Block,
                iso_codes: ["KP".to_string()].into(),
                countries: HashSet::new(),
                fail_closed: true,
            }],
        );

        let mut empty = make_ctx("", "");
        assert!(check.check(&mut empty).is_none());

        let mut none = make_ctx("", "");
        none.geo = None;
        assert!(check.check(&mut none).is_none());
    }

    #[test]
    fn no_geo_info_passes() {
        let check = GeoCheck::new();
        check.load_rules(
            "*",
            vec![GeoRule {
                id: "GEO-002".into(),
                name: "Block All".into(),
                mode: GeoRuleMode::Block,
                iso_codes: ["XX".to_string()].into(),
                countries: HashSet::new(),
                fail_closed: false,
            }],
        );
        let host_config = Arc::new(HostConfig::default());
        let mut ctx = RequestCtx {
            req_id: "t".into(),
            client_ip: "127.0.0.1".parse().unwrap(),
            peer_ip: "127.0.0.1".parse().unwrap(),
            client_port: 80,
            method: "GET".into(),
            host: "localhost".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
            device_fp: None,
            tx_velocity_token: None,
        };
        assert!(check.check(&mut ctx).is_none());
    }
}
