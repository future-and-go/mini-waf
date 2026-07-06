//! Contract tests for the panel configuration (`waf-panel.toml`) consumed by
//! the engine and proxy: shipped defaults, TOML round-trips, validation rules,
//! and disk loading.
//!
//! These live in waf-engine (rather than waf-common) so the behavior the
//! engine relies on — risk thresholds, honeypot paths, trusted-bypass CIDRs —
//! is pinned by the engine's own test suite.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::io::Write;
use std::path::Path;

use waf_common::panel_config::{
    AutoBlockPanel, PanelConfigError, PanelFileRef, RateLimitsPanel, ResponseFilteringPanel, TrustedBypassPanel,
    WafPanelConfig, load_panel_config,
};

#[test]
fn defaults_match_documented_values() {
    let c = WafPanelConfig::default();

    assert!(!c.shadow_mode);
    assert_eq!(c.risk_allow, 51);
    assert_eq!(c.risk_challenge, 74);
    assert_eq!(c.risk_block, 75);
    assert_eq!(c.challenge_type, "js_challenge");

    assert_eq!(c.honeypot_paths.len(), 6);
    assert!(c.honeypot_paths.contains(&"/.env".to_string()));
    assert!(c.honeypot_paths.contains(&"/.git/config".to_string()));
    assert!(c.honeypot_paths.contains(&"/actuator/env".to_string()));

    assert!(c.response_filtering.block_stack_traces);
    assert_eq!(
        c.response_filtering.json_redact_fields,
        vec!["password", "token", "secret", "api_key"]
    );

    assert_eq!(c.trusted_waf_bypass.cidrs, vec!["127.0.0.1/32", "::1/128"]);

    assert_eq!(c.rate_limits.default_rps, 100);
    assert_eq!(c.rate_limits.burst, 200);
    assert_eq!(c.rate_limits.session_expiry_secs, 3600);
    assert_eq!(c.rate_limits.global_rps, 0);
    assert_eq!(c.rate_limits.request_timeout_secs, 30);
    assert!(!c.rate_limits.fail_open);

    assert!(!c.auto_block.enabled);
    assert_eq!(c.auto_block.min_events, 5);
    assert_eq!(c.auto_block.window_secs, 60);
}

#[test]
fn sub_section_defaults_are_consistent_with_top_level() {
    // Each sub-struct's Default must match what WafPanelConfig::default() embeds.
    let c = WafPanelConfig::default();
    assert_eq!(c.response_filtering, ResponseFilteringPanel::default());
    assert_eq!(c.trusted_waf_bypass, TrustedBypassPanel::default());
    assert_eq!(c.rate_limits, RateLimitsPanel::default());
    assert_eq!(c.auto_block, AutoBlockPanel::default());
}

#[test]
fn default_config_passes_validation() {
    assert!(WafPanelConfig::default().validate().is_ok());
}

#[test]
fn empty_toml_yields_defaults() {
    let c = WafPanelConfig::from_toml_str("").expect("empty TOML parses");
    assert_eq!(c, WafPanelConfig::default());
}

#[test]
fn toml_round_trip_preserves_config() {
    let mut c = WafPanelConfig::default();
    c.shadow_mode = true;
    c.rate_limits.global_rps = 500;
    c.auto_block.enabled = true;

    let toml = c.to_toml_string().expect("serialize");
    let back = WafPanelConfig::from_toml_str(&toml).expect("parse");
    assert_eq!(c, back);
}

#[test]
fn unknown_fields_are_rejected() {
    let err = WafPanelConfig::from_toml_str("no_such_field = true").unwrap_err();
    assert!(err.to_string().contains("no_such_field"));
}

#[test]
fn from_toml_str_enforces_risk_ordering() {
    // risk_allow >= risk_challenge must be rejected at load time
    let err = WafPanelConfig::from_toml_str("risk_allow = 90").unwrap_err();
    assert!(err.to_string().contains("risk_allow < risk_challenge"));
}

#[test]
fn validate_rejects_equal_challenge_and_block() {
    let c = WafPanelConfig {
        risk_challenge: 75,
        risk_block: 75,
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::RiskOrdering)));
}

#[test]
fn validate_accepts_plain_ips_and_networks_as_trusted_cidrs() {
    let mut c = WafPanelConfig::default();
    c.trusted_waf_bypass.cidrs = vec![
        "192.168.1.1".to_string(),        // bare IPv4
        "10.0.0.0/8".to_string(),         // IPv4 network
        "2001:db8::1".to_string(),        // bare IPv6
        "2001:db8::/32".to_string(),      // IPv6 network
        "  172.16.0.0/12  ".to_string(),  // whitespace trimmed
    ];
    assert!(c.validate().is_ok());
}

#[test]
fn validate_rejects_malformed_cidr() {
    let mut c = WafPanelConfig::default();
    c.trusted_waf_bypass.cidrs = vec!["not-a-cidr".to_string()];
    match c.validate() {
        Err(PanelConfigError::BadCidr(raw, _)) => assert_eq!(raw, "not-a-cidr"),
        other => panic!("expected BadCidr, got {other:?}"),
    }
}

#[test]
fn validate_rejects_empty_cidr_entry() {
    let mut c = WafPanelConfig::default();
    c.trusted_waf_bypass.cidrs = vec!["   ".to_string()];
    match c.validate() {
        Err(PanelConfigError::BadCidr(_, reason)) => assert_eq!(reason, "empty"),
        other => panic!("expected BadCidr(empty), got {other:?}"),
    }
}

#[test]
fn validate_rejects_honeypot_path_without_leading_slash() {
    let mut c = WafPanelConfig::default();
    c.honeypot_paths = vec!["wp-admin".to_string()];
    assert!(matches!(c.validate(), Err(PanelConfigError::HoneypotPath)));
}

#[test]
fn validate_rejects_unsafe_json_redact_field_names() {
    for bad in ["1starts_with_digit", "", "has-dash", "has space", "ünïcode"] {
        let mut c = WafPanelConfig::default();
        c.response_filtering.json_redact_fields = vec![bad.to_string()];
        assert!(
            matches!(c.validate(), Err(PanelConfigError::RedactField)),
            "expected {bad:?} to be rejected"
        );
    }
}

#[test]
fn validate_accepts_safe_json_redact_field_names() {
    let mut c = WafPanelConfig::default();
    c.response_filtering.json_redact_fields =
        vec!["_private".to_string(), "camelCase2".to_string(), "snake_case".to_string()];
    assert!(c.validate().is_ok());
}

#[test]
fn error_messages_name_the_violated_rule() {
    assert!(
        PanelConfigError::RiskOrdering
            .to_string()
            .contains("risk_allow < risk_challenge < risk_block")
    );
    assert!(PanelConfigError::HoneypotPath.to_string().contains("start with '/'"));
    assert!(PanelConfigError::RedactField.to_string().contains("must match"));
    assert!(
        PanelConfigError::BadCidr("x".into(), "bad".into())
            .to_string()
            .contains("invalid trusted CIDR")
    );
}

#[test]
fn load_panel_config_returns_none_for_missing_file() {
    let result = load_panel_config(Path::new("/nonexistent/waf-panel.toml")).expect("missing file is not an error");
    assert!(result.is_none());
}

#[test]
fn load_panel_config_reads_valid_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("waf-panel.toml");
    let mut f = std::fs::File::create(&path).expect("create");
    writeln!(f, "shadow_mode = true\nrisk_allow = 10\nrisk_challenge = 20\nrisk_block = 30").expect("write");

    let loaded = load_panel_config(&path).expect("load").expect("present");
    assert!(loaded.shadow_mode);
    assert_eq!(loaded.risk_allow, 10);
    assert_eq!(loaded.risk_challenge, 20);
    assert_eq!(loaded.risk_block, 30);
}

#[test]
fn load_panel_config_rejects_invalid_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("waf-panel.toml");
    std::fs::write(&path, "risk_allow = \"not a number\"").expect("write");
    assert!(load_panel_config(&path).is_err());
}

#[test]
fn panel_file_ref_defaults_to_no_path() {
    let r = PanelFileRef::default();
    assert!(r.config_path.is_none());
}
