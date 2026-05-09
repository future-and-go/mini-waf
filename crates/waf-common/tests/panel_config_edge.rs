//! Edge-case coverage for `waf_common::panel_config`.

use std::io::Write;
use tempfile::NamedTempFile;
use waf_common::panel_config::{
    AutoBlockPanel, PanelConfigError, PanelFileRef, RateLimitsPanel, ResponseFilteringPanel, TrustedBypassPanel,
    WafPanelConfig, load_panel_config,
};

#[test]
fn panel_file_ref_default_empty() {
    let r = PanelFileRef::default();
    assert!(r.config_path.is_none());
}

#[test]
fn defaults_validate_clean() {
    let d = WafPanelConfig::default();
    assert!(d.validate().is_ok());
    assert_eq!(d.risk_allow, 51);
    assert_eq!(d.risk_challenge, 74);
    assert_eq!(d.risk_block, 75);
    assert_eq!(d.challenge_type, "js_challenge");
    assert!(d.honeypot_paths.iter().any(|p| p == "/.env"));
    assert!(d.response_filtering.block_stack_traces);
    assert!(
        d.response_filtering
            .json_redact_fields
            .contains(&"password".to_string())
    );
}

#[test]
fn rate_limits_and_auto_block_defaults() {
    let r = RateLimitsPanel::default();
    assert_eq!(r.default_rps, 100);
    assert_eq!(r.burst, 200);
    assert_eq!(r.session_expiry_secs, 3600);
    assert_eq!(r.global_rps, 0);
    assert_eq!(r.request_timeout_secs, 30);
    assert!(!r.fail_open);

    let a = AutoBlockPanel::default();
    assert!(!a.enabled);
    assert_eq!(a.min_events, 5);
    assert_eq!(a.window_secs, 60);
}

#[test]
fn trusted_bypass_default_includes_loopback() {
    let t = TrustedBypassPanel::default();
    assert!(t.cidrs.iter().any(|c| c == "127.0.0.1/32"));
    assert!(t.cidrs.iter().any(|c| c == "::1/128"));
}

#[test]
fn response_filtering_default_redacts_sensitive_fields() {
    let r = ResponseFilteringPanel::default();
    for f in ["password", "token", "secret", "api_key"] {
        assert!(r.json_redact_fields.iter().any(|x| x == f));
    }
}

#[test]
fn validate_rejects_inverted_risk_thresholds() {
    let c = WafPanelConfig {
        risk_allow: 80,
        risk_challenge: 70,
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::RiskOrdering)));
}

#[test]
fn validate_rejects_equal_risk_bands() {
    let c = WafPanelConfig {
        risk_allow: 50,
        risk_challenge: 50,
        risk_block: 70,
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::RiskOrdering)));
}

#[test]
fn validate_rejects_honeypot_path_without_slash() {
    let c = WafPanelConfig {
        honeypot_paths: vec!["no-leading-slash".into()],
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::HoneypotPath)));
}

#[test]
fn validate_rejects_bad_redact_field() {
    let c = WafPanelConfig {
        response_filtering: ResponseFilteringPanel {
            block_stack_traces: true,
            json_redact_fields: vec!["1starts-with-digit".into()],
        },
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::RedactField)));
}

#[test]
fn validate_rejects_redact_field_with_dot() {
    let c = WafPanelConfig {
        response_filtering: ResponseFilteringPanel {
            block_stack_traces: true,
            json_redact_fields: vec!["a.b".into()],
        },
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::RedactField)));
}

#[test]
fn validate_rejects_empty_redact_field() {
    let c = WafPanelConfig {
        response_filtering: ResponseFilteringPanel {
            block_stack_traces: true,
            json_redact_fields: vec![String::new()],
        },
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::RedactField)));
}

#[test]
fn validate_accepts_underscore_prefixed_redact_field() {
    let c = WafPanelConfig {
        response_filtering: ResponseFilteringPanel {
            block_stack_traces: true,
            json_redact_fields: vec!["_internal".into()],
        },
        ..Default::default()
    };
    assert!(c.validate().is_ok());
}

#[test]
fn validate_accepts_ip_literal_in_trusted() {
    let c = WafPanelConfig {
        trusted_waf_bypass: TrustedBypassPanel {
            cidrs: vec!["192.168.1.5".into(), "fe80::1".into()],
        },
        ..Default::default()
    };
    assert!(c.validate().is_ok());
}

#[test]
fn validate_rejects_empty_cidr_string() {
    let c = WafPanelConfig {
        trusted_waf_bypass: TrustedBypassPanel {
            cidrs: vec!["   ".into()],
        },
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::BadCidr(_, _))));
}

#[test]
fn validate_rejects_garbage_cidr() {
    let c = WafPanelConfig {
        trusted_waf_bypass: TrustedBypassPanel {
            cidrs: vec!["not-a-cidr-at-all".into()],
        },
        ..Default::default()
    };
    assert!(matches!(c.validate(), Err(PanelConfigError::BadCidr(_, _))));
}

#[test]
fn from_toml_str_rejects_unknown_field() {
    // `deny_unknown_fields` should reject typos at load time.
    let r = WafPanelConfig::from_toml_str("shadow_mode = false\nunknown_field = 1\n");
    assert!(r.is_err());
}

#[test]
fn from_toml_str_validation_runs_on_load() {
    let r =
        WafPanelConfig::from_toml_str("shadow_mode = false\nrisk_allow = 80\nrisk_challenge = 70\nrisk_block = 75\n");
    assert!(r.is_err());
}

#[test]
fn load_panel_config_returns_none_when_missing() {
    let path = std::path::PathBuf::from("/this/path/does/not/exist/panel.toml");
    let r = load_panel_config(&path).unwrap();
    assert!(r.is_none());
}

#[test]
fn load_panel_config_reads_and_validates() {
    let mut f = NamedTempFile::new().unwrap();
    let body = WafPanelConfig::default().to_toml_string().unwrap();
    write!(f, "{body}").unwrap();
    let r = load_panel_config(f.path()).unwrap();
    assert!(r.is_some());
    assert_eq!(r.unwrap(), WafPanelConfig::default());
}

#[test]
fn load_panel_config_propagates_invalid_toml() {
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "not = valid = at = all\n").unwrap();
    assert!(load_panel_config(f.path()).is_err());
}

#[test]
fn panel_config_error_display_strings() {
    let s = PanelConfigError::RiskOrdering.to_string();
    assert!(s.contains("risk"));
    let s = PanelConfigError::HoneypotPath.to_string();
    assert!(s.contains("/"));
    let s = PanelConfigError::RedactField.to_string();
    assert!(s.contains("JSON"));
    let s = PanelConfigError::BadCidr("x".into(), "y".into()).to_string();
    assert!(s.contains("CIDR"));
}
