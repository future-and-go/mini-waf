//! FR-002 end-to-end integration tests — tier classification + hot-reload.
//!
//! Scope: observable contract without booting Pingora.
//!   1. Build TierSnapshot from TOML fixture (4 tiers + 5 rules).
//!   2. Call `build_from_parts` via registry classify for each (path, method, tier) tuple.
//!   3. Assert ctx.tier and ctx.tier_policy.fail_mode match the TOML.
//!   4. Hot-reload: write TOML to tempfile, spawn TierConfigWatcher, edit file,
//!      sleep > debounce, assert next classify returns new tier.

// Integration tests: allow panic-capable code, doc nits, and non-const helpers.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::collections::HashMap;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use gateway::ctx_builder::request_ctx_builder::build_from_parts;
use gateway::tiered::tier_classifier::RequestParts;
use gateway::tiered::{DEFAULT_DEBOUNCE_MS, TierConfigWatcher, TierPolicyRegistry, TierSnapshot};
use http::{HeaderMap, Method};
use waf_common::HostConfig;
use waf_common::tier::{CachePolicy, FailMode, RiskThresholds, Tier, TierClassifierRule, TierConfig, TierPolicy};
use waf_common::tier_match::{HostMatch, PathMatch};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn risk(allow: u32, challenge: u32, block: u32) -> RiskThresholds {
    RiskThresholds {
        allow,
        challenge,
        block,
    }
}

fn policy(fail_mode: FailMode, ddos: u32, cache: CachePolicy, rt: RiskThresholds) -> TierPolicy {
    TierPolicy {
        fail_mode,
        ddos_threshold_rps: ddos,
        cache_policy: cache,
        risk_thresholds: rt,
    }
}

/// Build the canonical 4-tier config used across all E2E tests.
///
/// Rules (priority order, highest first):
///   1. path exact  /login + POST  → Critical  (priority 100)
///   2. path prefix /api/          → High      (priority 90)
///   3. host suffix .internal.com  → High      (priority 80, host rule)
///   4. path regex  ^/users/\d+$   → Medium    (priority 70)
///   5. path prefix /static/       → Medium    (priority 60)
///
/// Default tier = CatchAll.
fn fixture_config() -> TierConfig {
    let rules = vec![
        // Rule 1 — exact path + POST method → Critical
        TierClassifierRule {
            priority: 100,
            tier: Tier::Critical,
            host: None,
            path: Some(PathMatch::Exact { value: "/login".into() }),
            method: Some(vec![waf_common::tier::HttpMethod::Post]),
            headers: None,
        },
        // Rule 2 — prefix path /api/ → High
        TierClassifierRule {
            priority: 90,
            tier: Tier::High,
            host: None,
            path: Some(PathMatch::Prefix { value: "/api/".into() }),
            method: None,
            headers: None,
        },
        // Rule 3 — host suffix → High
        TierClassifierRule {
            priority: 80,
            tier: Tier::High,
            host: Some(HostMatch::Suffix {
                value: ".internal.com".into(),
            }),
            path: None,
            method: None,
            headers: None,
        },
        // Rule 4 — path regex → Medium
        TierClassifierRule {
            priority: 70,
            tier: Tier::Medium,
            host: None,
            path: Some(PathMatch::Regex {
                value: r"^/users/\d+$".into(),
            }),
            method: None,
            headers: None,
        },
        // Rule 5 — prefix /static/ → Medium
        TierClassifierRule {
            priority: 60,
            tier: Tier::Medium,
            host: None,
            path: Some(PathMatch::Prefix {
                value: "/static/".into(),
            }),
            method: None,
            headers: None,
        },
    ];

    let mut policies = HashMap::new();
    policies.insert(
        Tier::Critical,
        policy(FailMode::Close, 50, CachePolicy::NoCache, risk(10, 40, 70)),
    );
    policies.insert(
        Tier::High,
        policy(
            FailMode::Close,
            200,
            CachePolicy::ShortTtl { ttl_seconds: 30 },
            risk(20, 50, 80),
        ),
    );
    policies.insert(
        Tier::Medium,
        policy(
            FailMode::Open,
            1000,
            CachePolicy::Default { ttl_seconds: 300 },
            risk(30, 60, 85),
        ),
    );
    policies.insert(
        Tier::CatchAll,
        policy(
            FailMode::Open,
            u32::MAX,
            CachePolicy::Aggressive { ttl_seconds: 3600 },
            risk(35, 65, 90),
        ),
    );

    TierConfig {
        default_tier: Tier::CatchAll,
        classifier_rules: rules,
        policies,
    }
}

fn make_host_config(host: &str) -> Arc<HostConfig> {
    Arc::new(HostConfig {
        host: host.to_string(),
        port: 80,
        ssl: false,
        ..HostConfig::default()
    })
}

/// Classify via the registry and then wire the result through `build_from_parts`
/// so we exercise the full observable contract (ctx.tier, ctx.tier_policy).
fn classify_ctx(registry: &TierPolicyRegistry, host: &str, path: &str, method: &Method) -> (Tier, FailMode) {
    let headers = HeaderMap::new();
    let parts = RequestParts {
        host,
        path,
        method,
        headers: &headers,
    };
    let (tier, tier_policy) = registry.classify(&parts);
    let fail_mode = tier_policy.fail_mode;

    let ctx = build_from_parts(
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        12345,
        method.to_string(),
        path.to_string(),
        String::new(),
        HashMap::new(),
        0,
        false,
        make_host_config(host),
        tier,
        tier_policy,
    );

    (ctx.tier, fail_mode)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn e2e_all_four_tiers_reachable() {
    let snap = TierSnapshot::try_from_config(fixture_config()).unwrap();
    let registry = TierPolicyRegistry::new(snap);

    // Critical — POST /login
    let (tier, fail_mode) = classify_ctx(&registry, "example.com", "/login", &Method::POST);
    assert_eq!(tier, Tier::Critical, "POST /login must be Critical");
    assert_eq!(fail_mode, FailMode::Close, "Critical tier must fail-close");

    // High — GET /api/v1/users
    let (tier, fail_mode) = classify_ctx(&registry, "example.com", "/api/v1/users", &Method::GET);
    assert_eq!(tier, Tier::High, "GET /api/... must be High");
    assert_eq!(fail_mode, FailMode::Close, "High tier must fail-close");

    // Medium — GET /users/42 (regex match)
    let (tier, fail_mode) = classify_ctx(&registry, "example.com", "/users/42", &Method::GET);
    assert_eq!(tier, Tier::Medium, "GET /users/42 must be Medium via regex");
    assert_eq!(fail_mode, FailMode::Open, "Medium tier must fail-open");

    // CatchAll — no rule matches
    let (tier, fail_mode) = classify_ctx(&registry, "example.com", "/totally/unknown/path", &Method::GET);
    assert_eq!(tier, Tier::CatchAll, "unmatched request must fall to CatchAll");
    assert_eq!(fail_mode, FailMode::Open, "CatchAll tier must fail-open");
}

#[test]
fn e2e_default_tier_on_no_match() {
    let snap = TierSnapshot::try_from_config(fixture_config()).unwrap();
    let registry = TierPolicyRegistry::new(snap);

    // Various paths that don't match any explicit rule
    for path in ["/health", "/metrics", "/favicon.ico", "/robots.txt"] {
        let (tier, _) = classify_ctx(&registry, "example.com", path, &Method::GET);
        assert_eq!(tier, Tier::CatchAll, "path {path} should fall to CatchAll");
    }
}

#[test]
fn e2e_policy_fields_match_toml() {
    let snap = TierSnapshot::try_from_config(fixture_config()).unwrap();
    let registry = TierPolicyRegistry::new(snap);

    let headers = HeaderMap::new();
    let parts = RequestParts {
        host: "example.com",
        path: "/login",
        method: &Method::POST,
        headers: &headers,
    };
    let (tier, policy) = registry.classify(&parts);
    assert_eq!(tier, Tier::Critical);
    assert_eq!(policy.ddos_threshold_rps, 50);
    assert_eq!(policy.risk_thresholds.allow, 10);
    assert_eq!(policy.risk_thresholds.challenge, 40);
    assert_eq!(policy.risk_thresholds.block, 70);
    assert!(matches!(policy.cache_policy, CachePolicy::NoCache));

    // High tier
    let parts_high = RequestParts {
        host: "example.com",
        path: "/api/v1",
        method: &Method::GET,
        headers: &headers,
    };
    let (tier, policy) = registry.classify(&parts_high);
    assert_eq!(tier, Tier::High);
    assert_eq!(policy.ddos_threshold_rps, 200);
    assert!(matches!(policy.cache_policy, CachePolicy::ShortTtl { ttl_seconds: 30 }));
}

#[test]
fn e2e_host_rule_matches_internal_subdomain() {
    let snap = TierSnapshot::try_from_config(fixture_config()).unwrap();
    let registry = TierPolicyRegistry::new(snap);

    // Matches rule 3: host suffix .internal.com → High
    let (tier, _) = classify_ctx(&registry, "svc.internal.com", "/any/path", &Method::GET);
    assert_eq!(tier, Tier::High, "*.internal.com host suffix rule must match High");

    // Non-matching host falls through to default
    let (tier, _) = classify_ctx(&registry, "external.example.com", "/any/path", &Method::GET);
    assert_eq!(tier, Tier::CatchAll, "non-internal host without path match → CatchAll");
}

// ---------------------------------------------------------------------------
// TOML round-trip: build TierSnapshot from TOML string (validates schema)
// ---------------------------------------------------------------------------

const FIXTURE_TOML: &str = r#"
[tiered_protection]
default_tier = "catch_all"

[[tiered_protection.classifier_rules]]
priority = 100
tier     = "critical"
path     = { kind = "exact", value = "/login" }
method   = ["POST"]

[[tiered_protection.classifier_rules]]
priority = 90
tier     = "high"
path     = { kind = "prefix", value = "/api/" }

[[tiered_protection.classifier_rules]]
priority = 80
tier     = "high"
host     = { kind = "suffix", value = ".internal.com" }

[[tiered_protection.classifier_rules]]
priority = 70
tier     = "medium"
path     = { kind = "regex", value = "^/users/\\d+$" }

[[tiered_protection.classifier_rules]]
priority = 60
tier     = "medium"
path     = { kind = "prefix", value = "/static/" }

[tiered_protection.policies.critical]
fail_mode          = "close"
ddos_threshold_rps = 50
cache_policy       = { mode = "no_cache" }
risk_thresholds    = { allow = 10, challenge = 40, block = 70 }

[tiered_protection.policies.high]
fail_mode          = "close"
ddos_threshold_rps = 200
cache_policy       = { mode = "short_ttl", ttl_seconds = 30 }
risk_thresholds    = { allow = 20, challenge = 50, block = 80 }

[tiered_protection.policies.medium]
fail_mode          = "open"
ddos_threshold_rps = 1000
cache_policy       = { mode = "default", ttl_seconds = 300 }
risk_thresholds    = { allow = 30, challenge = 60, block = 85 }

[tiered_protection.policies.catch_all]
fail_mode          = "open"
ddos_threshold_rps = 4294967295
cache_policy       = { mode = "aggressive", ttl_seconds = 3600 }
risk_thresholds    = { allow = 35, challenge = 65, block = 90 }
"#;

/// Wrapper matching the TOML envelope used by `try_reload`.
#[derive(serde::Deserialize)]
struct TomlEnvelope {
    tiered_protection: waf_common::tier::TierConfig,
}

#[test]
fn e2e_toml_round_trip_builds_valid_snapshot() {
    let env: TomlEnvelope = toml::from_str(FIXTURE_TOML).expect("TOML must parse");
    let snap = TierSnapshot::try_from_config(env.tiered_protection).expect("snapshot must build");
    assert_eq!(snap.classifier.rule_count(), 5);
    assert_eq!(snap.policies.len(), 4);
}

// ---------------------------------------------------------------------------
// Hot-reload test: edit tempfile → assert new policy active
// ---------------------------------------------------------------------------

fn write_toml(path: &std::path::Path, ddos_rps: u32) {
    let content = format!(
        r#"
[tiered_protection]
default_tier = "catch_all"

[tiered_protection.policies.critical]
fail_mode          = "close"
ddos_threshold_rps = {ddos_rps}
cache_policy       = {{ mode = "no_cache" }}
risk_thresholds    = {{ allow = 10, challenge = 40, block = 70 }}

[tiered_protection.policies.high]
fail_mode          = "close"
ddos_threshold_rps = {ddos_rps}
cache_policy       = {{ mode = "short_ttl", ttl_seconds = 30 }}
risk_thresholds    = {{ allow = 20, challenge = 50, block = 80 }}

[tiered_protection.policies.medium]
fail_mode          = "open"
ddos_threshold_rps = {ddos_rps}
cache_policy       = {{ mode = "default", ttl_seconds = 300 }}
risk_thresholds    = {{ allow = 30, challenge = 60, block = 85 }}

[tiered_protection.policies.catch_all]
fail_mode          = "open"
ddos_threshold_rps = {ddos_rps}
cache_policy       = {{ mode = "aggressive", ttl_seconds = 3600 }}
risk_thresholds    = {{ allow = 35, challenge = 65, block = 90 }}
"#
    );
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .create(true)
        .open(path)
        .unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
}

#[test]
fn e2e_hot_reload_changes_policy() {
    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("tier_test.toml");

    // Write initial config with ddos_threshold_rps = 100
    write_toml(&config_path, 100);

    // Build initial snapshot and registry
    let snap = gateway::tiered::tier_config_watcher::try_reload(&config_path).unwrap();
    let registry = Arc::new(TierPolicyRegistry::new(snap));

    // Verify initial value
    let headers = HeaderMap::new();
    let parts = RequestParts {
        host: "example.com",
        path: "/any",
        method: &Method::GET,
        headers: &headers,
    };
    let (_, initial_policy) = registry.classify(&parts);
    assert_eq!(
        initial_policy.ddos_threshold_rps, 100,
        "initial ddos_threshold_rps must be 100"
    );

    // Spawn the watcher
    let _watcher = TierConfigWatcher::spawn(config_path.clone(), Arc::clone(&registry), DEFAULT_DEBOUNCE_MS).unwrap();

    // Edit the config file — change ddos_threshold_rps to 999
    write_toml(&config_path, 999);

    // Sleep > debounce to let the watcher pick up the change
    std::thread::sleep(Duration::from_millis(DEFAULT_DEBOUNCE_MS * 3));

    // Assert new policy is active
    let (_, new_policy) = registry.classify(&parts);
    assert_eq!(
        new_policy.ddos_threshold_rps, 999,
        "hot-reload must update ddos_threshold_rps to 999"
    );
}
