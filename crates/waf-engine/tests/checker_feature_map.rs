use waf_common::types::Phase;
use waf_engine::interop::FeatureCatalog;
use waf_engine::interop::checker_feature_map::phase_feature_identity;

// Keep in sync with Phase enum in waf-common/src/types.rs
const ALL_PHASES: [Phase; 24] = [
    Phase::IpWhitelist,
    Phase::IpBlacklist,
    Phase::UrlWhitelist,
    Phase::UrlBlacklist,
    Phase::SqlInjection,
    Phase::Xss,
    Phase::Rce,
    Phase::Scanner,
    Phase::DirTraversal,
    Phase::Bot,
    Phase::RateLimit,
    Phase::CustomRule,
    Phase::Owasp,
    Phase::Sensitive,
    Phase::AntiHotlink,
    Phase::CrowdSec,
    Phase::GeoIp,
    Phase::Community,
    Phase::Ddos,
    Phase::RiskScore,
    Phase::Ssrf,
    Phase::HeaderInjection,
    Phase::BruteForce,
    Phase::RequestBodyAbuse,
];

#[test]
fn every_phase_maps_to_valid_catalog_feature() {
    for phase in ALL_PHASES {
        let (feature, _policy) = phase_feature_identity(phase);
        assert!(
            FeatureCatalog::feature_exists(feature),
            "{phase:?} mapped to unknown feature {feature:?}",
        );
    }
}

#[test]
fn every_phase_policy_is_valid_when_present() {
    for phase in ALL_PHASES {
        let (feature, policy) = phase_feature_identity(phase);
        if let Some(p) = policy {
            assert!(
                FeatureCatalog::policy_exists(feature, p),
                "{phase:?} mapped to unknown policy {p:?} under feature {feature:?}",
            );
        }
    }
}

#[test]
fn custom_rule_has_no_policy() {
    let (_feature, policy) = phase_feature_identity(Phase::CustomRule);
    assert!(
        policy.is_none(),
        "CustomRule should have None policy (spans yaml/rhai/wasm)",
    );
}

#[test]
fn all_24_phases_covered() {
    assert_eq!(ALL_PHASES.len(), 24);
    let mut seen = std::collections::HashSet::new();
    for phase in ALL_PHASES {
        let (feature, _) = phase_feature_identity(phase);
        seen.insert(feature);
    }
    assert!(
        seen.len() >= 10,
        "expected at least 10 distinct features, got {}",
        seen.len(),
    );
}
