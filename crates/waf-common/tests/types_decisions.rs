//! Coverage for `waf_common::types` decisions, defaults, Display, serde.

use waf_common::types::{
    DefenseConfig, DetectionResult, GeoIpInfo, HostConfig, LoadBalanceStrategy, Phase, RequestCtx, WafAction,
    WafDecision, parse_cookie_header,
};

#[test]
fn waf_decision_allow_constructor() {
    let d = WafDecision::allow();
    assert!(d.is_allowed());
    assert!(d.result.is_none());
    assert!(matches!(d.action, WafAction::Allow));
}

#[test]
fn waf_decision_block_constructor() {
    let r = DetectionResult {
        rule_id: Some("R1".into()),
        rule_name: "test".into(),
        phase: Phase::SqlInjection,
        detail: "found".into(),
        rule_action: None,
        action_status: None,
    };
    let d = WafDecision::block(403, Some("denied".into()), r);
    assert!(!d.is_allowed());
    assert!(d.result.is_some());
    match d.action {
        WafAction::Block { status, body } => {
            assert_eq!(status, 403);
            assert_eq!(body.as_deref(), Some("denied"));
        }
        _ => panic!("expected Block"),
    }
}

#[test]
fn waf_decision_log_only_is_allowed() {
    let d = WafDecision {
        action: WafAction::LogOnly,
        result: None,
    };
    assert!(d.is_allowed());
}

#[test]
fn waf_decision_block_action_not_allowed() {
    let d = WafDecision {
        action: WafAction::Block {
            status: 429,
            body: None,
        },
        result: None,
    };
    assert!(!d.is_allowed());
}

#[test]
fn waf_action_serde_tagged_snake_case() {
    let s = serde_json::to_string(&WafAction::Allow).unwrap();
    assert!(s.contains("\"allow\""));

    let s = serde_json::to_string(&WafAction::LogOnly).unwrap();
    assert!(s.contains("\"log_only\""));

    let s = serde_json::to_string(&WafAction::Challenge).unwrap();
    assert!(s.contains("\"challenge\""));

    let s = serde_json::to_string(&WafAction::Redirect { url: "http://x".into() }).unwrap();
    assert!(s.contains("\"redirect\""));
    assert!(s.contains("http://x"));

    let back: WafAction = serde_json::from_str(r#"{"type":"allow"}"#).unwrap();
    assert!(matches!(back, WafAction::Allow));
}

#[test]
fn phase_display_covers_all_variants() {
    let cases = [
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
    ];
    for (p, want) in cases {
        assert_eq!(p.to_string(), want, "phase {p:?}");
    }
}

#[test]
fn phase_discriminants_are_stable() {
    assert_eq!(Phase::IpWhitelist as u8, 1);
    assert_eq!(Phase::SqlInjection as u8, 5);
    assert_eq!(Phase::RiskScore as u8, 20);
}

#[test]
fn host_config_default_round_trip_serde() {
    let h = HostConfig::default();
    assert_eq!(h.port, 80);
    assert_eq!(h.remote_port, 8080);
    assert!(h.preserve_host);
    assert!(!h.strip_server_header);
    assert!(matches!(h.load_balance_strategy, LoadBalanceStrategy::RoundRobin));
    assert!(h.header_blocklist.contains(&"x-powered-by-waf".to_string()));
    assert_eq!(h.mask_token, "[redacted]");
    assert_eq!(h.body_mask_max_bytes, 1024 * 1024);

    let json = serde_json::to_string(&h).unwrap();
    let back: HostConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.port, h.port);
    assert_eq!(back.body_mask_max_bytes, h.body_mask_max_bytes);
}

#[test]
fn defense_config_defaults() {
    let d = DefenseConfig::default();
    assert!(d.bot && d.sqli && d.xss && d.scan && d.rce && d.sensitive);
    assert!(d.dir_traversal);
    assert!(!d.owasp_set);
    assert!(d.cc);
    assert!((d.cc_rps - 100.0).abs() < f64::EPSILON);
    assert_eq!(d.cc_burst, 200);
    assert_eq!(d.cc_ban_threshold, 10);
    assert_eq!(d.cc_ban_duration_secs, 300);
    assert_eq!(d.owasp_paranoia, 1);
    assert!(!d.block_scripted_clients);
}

#[test]
fn load_balance_strategy_serde_snake_case() {
    let s = serde_json::to_string(&LoadBalanceStrategy::IpHash).unwrap();
    assert!(s.contains("\"ip_hash\""));
    let s = serde_json::to_string(&LoadBalanceStrategy::WeightedRoundRobin).unwrap();
    assert!(s.contains("\"weighted_round_robin\""));
    let s = serde_json::to_string(&LoadBalanceStrategy::LeastConnections).unwrap();
    assert!(s.contains("\"least_connections\""));
    let s = serde_json::to_string(&LoadBalanceStrategy::RoundRobin).unwrap();
    assert!(s.contains("\"round_robin\""));
}

#[test]
fn geoip_info_default() {
    let g = GeoIpInfo::default();
    assert!(g.country.is_empty());
    assert!(g.iso_code.is_empty());
}

#[test]
fn parse_cookie_header_unicode_value() {
    let m = parse_cookie_header("locale=日本語; theme=dark");
    assert_eq!(m.get("locale").map(String::as_str), Some("日本語"));
    assert_eq!(m.get("theme").map(String::as_str), Some("dark"));
}

#[test]
fn parse_cookie_header_oversize_returns_all() {
    let val = "x".repeat(8192);
    let header = format!("big={val}; small=ok");
    let m = parse_cookie_header(&header);
    assert_eq!(m.get("big").map(String::len), Some(8192));
    assert_eq!(m.get("small").map(String::as_str), Some("ok"));
}

#[test]
fn default_tier_policy_is_shared_arc() {
    let a = RequestCtx::default_tier_policy();
    let b = RequestCtx::default_tier_policy();
    assert!(std::sync::Arc::ptr_eq(&a, &b));
}
