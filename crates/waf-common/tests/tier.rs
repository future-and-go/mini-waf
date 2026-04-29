//! Phase 1 acceptance tests for tier types + TOML schema.

use std::collections::HashMap;

use waf_common::tier::{
    CachePolicy, FailMode, HttpMethod, RiskThresholds, Tier, TierClassifierRule, TierConfig, TierConfigError,
    TierPolicy,
};
use waf_common::tier_match::{HostMatch, PathMatch};

#[derive(serde::Deserialize)]
struct Wrapper {
    tiered_protection: TierConfig,
}

const FIXTURE: &str = include_str!("fixtures/tiered_protection.toml");

const fn make_policy(allow: u32, challenge: u32, block: u32) -> TierPolicy {
    TierPolicy {
        fail_mode: FailMode::Close,
        ddos_threshold_rps: 100,
        cache_policy: CachePolicy::NoCache,
        risk_thresholds: RiskThresholds {
            allow,
            challenge,
            block,
        },
    }
}

fn full_policies() -> HashMap<Tier, TierPolicy> {
    let mut m = HashMap::new();
    for t in Tier::ALL {
        m.insert(t, make_policy(10, 20, 30));
    }
    m
}

#[test]
fn parses_valid_toml() {
    let parsed: Wrapper = toml::from_str(FIXTURE).expect("fixture must deserialize");
    let cfg = parsed.tiered_protection;

    assert_eq!(cfg.default_tier, Tier::CatchAll);
    assert_eq!(cfg.classifier_rules.len(), 4);
    assert_eq!(cfg.policies.len(), 4);

    // Spot-check rule 0 — `/login` POST → critical.
    let r0 = cfg.classifier_rules.first().expect("rule 0 exists");
    assert_eq!(r0.priority, 100);
    assert_eq!(r0.tier, Tier::Critical);
    assert!(matches!(&r0.path, Some(PathMatch::Exact { value }) if value == "/login"));
    assert_eq!(r0.method.as_deref(), Some(&[HttpMethod::Post][..]));

    // Spot-check critical policy — close + no_cache.
    let crit = cfg.policies.get(&Tier::Critical).unwrap();
    assert_eq!(crit.fail_mode, FailMode::Close);
    assert!(matches!(crit.cache_policy, CachePolicy::NoCache));

    cfg.validate().expect("fixture must validate");
}

#[test]
fn validate_rejects_missing_tier_policy() {
    let mut policies = full_policies();
    policies.remove(&Tier::High);
    let cfg = TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: vec![],
        policies,
    };
    match cfg.validate() {
        Err(TierConfigError::MissingPolicy(Tier::High)) => {}
        other => panic!("expected MissingPolicy(High), got {other:?}"),
    }
}

#[test]
fn validate_rejects_bad_regex() {
    let cfg = TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: vec![TierClassifierRule {
            priority: 1,
            tier: Tier::High,
            host: None,
            path: Some(PathMatch::Regex {
                value: "([".to_string(), // invalid regex
            }),
            method: None,
            headers: None,
        }],
        policies: full_policies(),
    };
    match cfg.validate() {
        Err(TierConfigError::BadRegex { rule_idx: 0, .. }) => {}
        other => panic!("expected BadRegex on rule 0, got {other:?}"),
    }
}

#[test]
fn validate_rejects_bad_host_regex() {
    let cfg = TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: vec![TierClassifierRule {
            priority: 1,
            tier: Tier::High,
            host: Some(HostMatch::Regex {
                value: "*broken".into(),
            }),
            path: None,
            method: None,
            headers: None,
        }],
        policies: full_policies(),
    };
    assert!(matches!(
        cfg.validate(),
        Err(TierConfigError::BadRegex { rule_idx: 0, .. })
    ));
}

#[test]
fn validate_rejects_inverted_thresholds() {
    let mut policies = full_policies();
    policies.insert(Tier::Medium, make_policy(50, 30, 60)); // allow > challenge
    let cfg = TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: vec![],
        policies,
    };
    match cfg.validate() {
        Err(TierConfigError::InvalidThresholds { tier: Tier::Medium }) => {}
        other => panic!("expected InvalidThresholds(Medium), got {other:?}"),
    }
}

#[test]
fn tier_serde_roundtrip() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Holder {
        tier: Tier,
    }
    for t in Tier::ALL {
        let s = toml::to_string(&Holder { tier: t }).unwrap();
        let back: Holder = toml::from_str(&s).unwrap();
        assert_eq!(t, back.tier);
    }
    // Sanity: snake_case form for the multi-word variant.
    let s = toml::to_string(&Holder { tier: Tier::CatchAll }).unwrap();
    assert!(s.contains("\"catch_all\""), "got: {s}");
}
