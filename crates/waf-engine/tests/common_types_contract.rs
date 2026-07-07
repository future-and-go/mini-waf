//! Contract tests for the shared decision/action types the engine produces
//! and the gateway enforces: `WafAction`/`InteropMode` contract strings,
//! `RuleAction` translation, `WafDecision` constructors and enforcement
//! semantics, host-config defaults, and cookie-header parsing.
//!
//! These live in waf-engine so its own suite pins the cross-crate contract
//! it emits (`X-WAF-Action`, decision modes, phase names).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default,
    deprecated
)]

use waf_common::types::{
    DetectionResult, HostConfig, HostResponseFilter, HostUpstreamTimeoutError, InteropMode, Phase, RequestCtx,
    RuleAction, UpstreamAlpn, WafAction, WafDecision, parse_cookie_header,
};

fn detection(rule_id: Option<&str>) -> DetectionResult {
    DetectionResult {
        rule_id: rule_id.map(str::to_string),
        rule_name: "test-rule".to_string(),
        phase: Phase::SqlInjection,
        detail: "detail".to_string(),
        rule_action: None,
        action_status: None,
    }
}

// ── parse_cookie_header ────────────────────────────────────────────────────────

#[test]
fn cookie_header_parses_pairs_and_trims_whitespace() {
    let cookies = parse_cookie_header("  a=1; b = 2 ;c=3");
    assert_eq!(cookies.len(), 3);
    assert_eq!(cookies["a"], "1");
    assert_eq!(cookies["b"], "2");
    assert_eq!(cookies["c"], "3");
}

#[test]
fn cookie_header_drops_malformed_pairs_without_panicking() {
    // empty segments, missing '=', empty name — all silently dropped
    let cookies = parse_cookie_header(";; novalue ; =orphan; ok=yes");
    assert_eq!(cookies.len(), 1);
    assert_eq!(cookies["ok"], "yes");
}

#[test]
fn cookie_header_keeps_equals_inside_value_and_is_case_sensitive() {
    let cookies = parse_cookie_header("token=a=b=c; Token=other");
    assert_eq!(cookies["token"], "a=b=c");
    assert_eq!(cookies["Token"], "other");
}

#[test]
fn cookie_header_empty_input_yields_empty_map() {
    assert!(parse_cookie_header("").is_empty());
}

// ── WafAction contract strings ─────────────────────────────────────────────────

#[test]
fn waf_action_contract_strings_cover_all_variants() {
    assert_eq!(WafAction::Allow.as_contract_str(), "allow");
    assert_eq!(
        WafAction::Block {
            status: 403,
            body: None
        }
        .as_contract_str(),
        "block"
    );
    assert_eq!(WafAction::Challenge.as_contract_str(), "challenge");
    assert_eq!(
        WafAction::RateLimit {
            status: 429,
            body: None
        }
        .as_contract_str(),
        "rate_limit"
    );
    assert_eq!(WafAction::Timeout { status: 504 }.as_contract_str(), "timeout");
    assert_eq!(
        WafAction::CircuitBreaker {
            status: 503,
            body: None
        }
        .as_contract_str(),
        "circuit_breaker"
    );
    // Internal variants map to "allow" on the wire
    assert_eq!(WafAction::Redirect { url: "/x".into() }.as_contract_str(), "allow");
    assert_eq!(WafAction::LogOnly.as_contract_str(), "allow");
}

// ── RuleAction parsing and translation ─────────────────────────────────────────

#[test]
fn rule_action_parse_str_is_case_insensitive_and_defaults_to_block() {
    assert_eq!(RuleAction::parse_str("allow"), RuleAction::Allow);
    assert_eq!(RuleAction::parse_str("LOG"), RuleAction::Log);
    assert_eq!(RuleAction::parse_str("Challenge"), RuleAction::Challenge);
    assert_eq!(RuleAction::parse_str("block"), RuleAction::Block);
    assert_eq!(RuleAction::parse_str("deny"), RuleAction::Block);
    assert_eq!(RuleAction::parse_str(""), RuleAction::Block);
}

#[test]
fn rule_action_translates_to_waf_action() {
    assert!(matches!(
        RuleAction::Block.to_waf_action(403, Some("body".into())),
        WafAction::Block { status: 403, body: Some(b) } if b == "body"
    ));
    // Allow and Log both pass the request through; log-only is a mode, not an action
    assert!(matches!(RuleAction::Allow.to_waf_action(0, None), WafAction::Allow));
    assert!(matches!(RuleAction::Log.to_waf_action(0, None), WafAction::Allow));
    assert!(matches!(
        RuleAction::Challenge.to_waf_action(0, None),
        WafAction::Challenge
    ));
}

// ── InteropMode contract strings ───────────────────────────────────────────────

#[test]
fn interop_mode_contract_strings_round_trip() {
    assert_eq!(InteropMode::default(), InteropMode::Enforce);
    for mode in [InteropMode::Enforce, InteropMode::LogOnly] {
        assert_eq!(InteropMode::from_contract_str(mode.as_contract_str()), Some(mode));
    }
    assert_eq!(InteropMode::Enforce.as_contract_str(), "enforce");
    assert_eq!(InteropMode::LogOnly.as_contract_str(), "log_only");
    assert_eq!(InteropMode::from_contract_str("bogus"), None);
}

// ── WafDecision constructors and enforcement semantics ─────────────────────────

#[test]
fn decision_allow_is_neutral() {
    let d = WafDecision::allow();
    assert!(matches!(d.action, WafAction::Allow));
    assert!(d.result.is_none());
    assert_eq!(d.risk_score, 0);
    assert_eq!(d.mode, InteropMode::Enforce);
    assert!(d.rule_id.is_none());
    assert!(d.is_enforcement_allowed());
}

#[test]
fn decision_block_propagates_rule_id_from_detection() {
    let d = WafDecision::block(403, Some("denied".into()), detection(Some("rule-7")));
    assert!(matches!(d.action, WafAction::Block { status: 403, .. }));
    assert_eq!(d.rule_id.as_deref(), Some("rule-7"));
    assert!(!d.is_enforcement_allowed());
    assert_eq!(d.result.unwrap().rule_name, "test-rule");
}

#[test]
fn decision_rate_limit_propagates_rule_id() {
    let d = WafDecision::rate_limit(429, None, detection(Some("rl-1")));
    assert!(matches!(d.action, WafAction::RateLimit { status: 429, .. }));
    assert_eq!(d.rule_id.as_deref(), Some("rl-1"));
    assert!(!d.is_enforcement_allowed());
}

#[test]
fn decision_timeout_and_circuit_breaker_have_no_detection() {
    let t = WafDecision::timeout(504);
    assert!(matches!(t.action, WafAction::Timeout { status: 504 }));
    assert!(t.result.is_none());
    assert!(!t.is_enforcement_allowed());

    let cb = WafDecision::circuit_breaker(503, Some("tripped".into()));
    assert!(matches!(cb.action, WafAction::CircuitBreaker { status: 503, .. }));
    assert!(cb.result.is_none());
    assert!(!cb.is_enforcement_allowed());
}

#[test]
fn decision_builders_chain_risk_score_and_mode() {
    let d = WafDecision::allow().with_risk_score(42).with_mode(InteropMode::LogOnly);
    assert_eq!(d.risk_score, 42);
    assert_eq!(d.mode, InteropMode::LogOnly);
}

#[test]
fn log_only_mode_bypasses_enforcement_of_blocking_actions() {
    let blocked = WafDecision::block(403, None, detection(None));
    assert!(!blocked.is_enforcement_allowed());
    let observed = blocked.with_mode(InteropMode::LogOnly);
    assert!(observed.is_enforcement_allowed());
    // deprecated alias delegates to the mode-aware check
    assert!(observed.is_allowed());
}

// ── Phase display names ────────────────────────────────────────────────────────

#[test]
fn phase_display_names_are_stable() {
    let expected = [
        (Phase::IpWhitelist, "IP Whitelist"),
        (Phase::IpBlacklist, "IP Blacklist"),
        (Phase::UrlWhitelist, "URL Whitelist"),
        (Phase::UrlBlacklist, "URL Blacklist"),
        (Phase::SqlInjection, "SQL Injection"),
        (Phase::Xss, "XSS"),
        (Phase::Rce, "RCE"),
        (Phase::Scanner, "Scanner"),
        (Phase::DirTraversal, "Directory Traversal"),
        (Phase::Bot, "Bot"),
        (Phase::RateLimit, "Rate Limit"),
        (Phase::CustomRule, "Custom Rule"),
        (Phase::Owasp, "OWASP CRS"),
        (Phase::Sensitive, "Sensitive Data"),
        (Phase::AntiHotlink, "Anti-Hotlink"),
        (Phase::CrowdSec, "CrowdSec"),
        (Phase::GeoIp, "GeoIP"),
        (Phase::Community, "Community"),
        (Phase::Ddos, "DDoS"),
        (Phase::RiskScore, "Risk Score"),
        (Phase::Ssrf, "SSRF"),
        (Phase::HeaderInjection, "Header Injection"),
        (Phase::BruteForce, "Brute Force"),
        (Phase::RequestBodyAbuse, "Request Body Abuse"),
    ];
    for (phase, name) in expected {
        assert_eq!(phase.to_string(), name);
    }
}

// ── UpstreamAlpn DB strings ────────────────────────────────────────────────────

#[test]
fn upstream_alpn_db_strings_round_trip_and_unknown_falls_back() {
    assert_eq!(UpstreamAlpn::default(), UpstreamAlpn::H2H1);
    for alpn in [UpstreamAlpn::H1Only, UpstreamAlpn::H2H1, UpstreamAlpn::H2Only] {
        assert_eq!(UpstreamAlpn::from_db_str(alpn.as_db_str()), alpn);
    }
    assert_eq!(UpstreamAlpn::from_db_str("spdy"), UpstreamAlpn::H2H1);
}

// ── HostConfig defaults, timeout validation, response-filter override ──────────

#[test]
fn host_config_default_is_transparent_proxy_posture() {
    let h = HostConfig::default();
    assert_eq!(h.port, 80);
    assert!(!h.ssl);
    assert!(h.guard_status);
    assert!(h.start_status);
    assert!(h.preserve_host);
    assert!(!h.strip_server_header);
    assert!(!h.log_only_mode);
    assert!(!h.body_scan_enabled);
    assert_eq!(h.upstream_alpn, UpstreamAlpn::H2H1);
    assert!(h.validate_upstream_timeouts().is_ok());
}

#[test]
fn host_config_rejects_connect_timeout_exceeding_total() {
    let mut h = HostConfig::default();
    h.upstream_connect_timeout_ms = 10_000;
    h.upstream_total_connection_timeout_ms = 5_000;
    let err = h.validate_upstream_timeouts().unwrap_err();
    assert_eq!(
        err,
        HostUpstreamTimeoutError::ConnectExceedsTotal {
            connect: 10_000,
            total: 5_000,
        }
    );
    assert!(err.to_string().contains("connect must be <= total"));
}

#[test]
fn apply_response_filter_copies_the_five_admin_fields() {
    let mut h = HostConfig::default();
    let rf = HostResponseFilter {
        body_scan_enabled: true,
        body_scan_max_body_bytes: 1234,
        internal_patterns: vec!["secret-\\d+".to_string()],
        header_blocklist: vec!["x-internal".to_string()],
        strip_server_header: true,
    };
    h.apply_response_filter(&rf);
    assert!(h.body_scan_enabled);
    assert_eq!(h.body_scan_max_body_bytes, 1234);
    assert_eq!(h.internal_patterns, vec!["secret-\\d+"]);
    assert_eq!(h.header_blocklist, vec!["x-internal"]);
    assert!(h.strip_server_header);
}

#[test]
fn host_response_filter_defaults_match_host_config_defaults() {
    let rf = HostResponseFilter::default();
    let h = HostConfig::default();
    assert_eq!(rf.body_scan_enabled, h.body_scan_enabled);
    assert_eq!(rf.body_scan_max_body_bytes, h.body_scan_max_body_bytes);
    assert_eq!(rf.internal_patterns, h.internal_patterns);
    assert_eq!(rf.header_blocklist, h.header_blocklist);
    assert_eq!(rf.strip_server_header, h.strip_server_header);
}

// ── RequestCtx default fixture ─────────────────────────────────────────────────

#[test]
fn request_ctx_default_is_neutral_and_shares_tier_policy() {
    let ctx = RequestCtx::default();
    assert!(ctx.req_id.is_empty());
    assert!(ctx.client_ip.is_unspecified());
    assert!(!ctx.is_tls);
    assert!(ctx.cookies.is_empty());
    assert!(ctx.geo.is_none());
    // The process-wide default tier policy is cached and shared
    let a = RequestCtx::default_tier_policy();
    let b = RequestCtx::default_tier_policy();
    assert!(std::sync::Arc::ptr_eq(&a, &b));
}
