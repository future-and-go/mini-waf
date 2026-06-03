use waf_common::types::Phase;

/// Maps a detection [`Phase`] to its (feature, policy) identity in the
/// feature catalog. The exhaustive match ensures the compiler rejects
/// any new [`Phase`] variant that lacks a mapping.
#[must_use]
pub const fn phase_feature_identity(phase: Phase) -> (&'static str, Option<&'static str>) {
    match phase {
        Phase::IpWhitelist => ("access_control", Some("ip_whitelist")),
        Phase::IpBlacklist => ("access_control", Some("ip_blacklist")),
        Phase::UrlWhitelist => ("access_control", Some("url_whitelist")),
        Phase::UrlBlacklist => ("access_control", Some("url_blacklist")),
        Phase::SqlInjection => ("injection_control", Some("sqli")),
        Phase::Xss => ("injection_control", Some("xss")),
        Phase::Rce => ("injection_control", Some("rce")),
        Phase::Scanner => ("bot_detection", Some("scanner")),
        Phase::DirTraversal => ("path_traversal", Some("dir_traversal")),
        Phase::Bot => ("bot_detection", Some("bot")),
        Phase::RateLimit => ("rate_limiting", Some("per_ip")),
        Phase::CustomRule => ("custom_rules", None),
        Phase::Owasp => ("owasp_rules", Some("core_ruleset")),
        Phase::Sensitive => ("data_protection", Some("sensitive_data")),
        Phase::AntiHotlink => ("data_protection", Some("anti_hotlink")),
        Phase::CrowdSec => ("reputation", Some("crowdsec")),
        Phase::GeoIp => ("geo_protection", Some("geo_blocking")),
        Phase::Community => ("reputation", Some("community_blocklist")),
        Phase::Ddos => ("ddos_protection", Some("per_ip_burst")),
        Phase::RiskScore => ("risk_assessment", Some("cumulative_risk")),
        Phase::Ssrf => ("network_protection", Some("ssrf")),
        Phase::HeaderInjection => ("network_protection", Some("header_injection")),
        Phase::BruteForce => ("auth_protection", Some("brute_force")),
        Phase::RequestBodyAbuse => ("payload_protection", Some("body_abuse")),
    }
}
