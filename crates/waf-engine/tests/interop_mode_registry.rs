use std::sync::Arc;

use waf_engine::interop::{InteropMode, ModeRegistry};

#[test]
fn default_mode_is_enforce() {
    let reg = ModeRegistry::new();
    assert_eq!(reg.resolve("injection_control", None), InteropMode::Enforce);
    assert_eq!(reg.resolve("rate_limiting", Some("per_ip")), InteropMode::Enforce);
}

#[test]
fn set_all_log_only() {
    let reg = ModeRegistry::new();
    reg.set_all(InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("rate_limiting", Some("per_ip")), InteropMode::LogOnly);
}

#[test]
fn set_all_enforce_clears_overrides() {
    let reg = ModeRegistry::new();
    reg.set_feature("injection_control", InteropMode::LogOnly);
    reg.set_policy("injection_control", "sqli", InteropMode::LogOnly);
    reg.set_all(InteropMode::Enforce);
    let snap = reg.snapshot();
    assert!(snap.feature_overrides.is_empty());
    assert!(snap.policy_overrides.is_empty());
    assert_eq!(snap.default_mode, InteropMode::Enforce);
}

#[test]
fn feature_override_over_default() {
    let reg = ModeRegistry::new();
    reg.set_feature("injection_control", InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("rate_limiting", None), InteropMode::Enforce);
}

#[test]
fn policy_override_over_feature() {
    let reg = ModeRegistry::new();
    reg.set_feature("injection_control", InteropMode::LogOnly);
    reg.set_policy("injection_control", "xss", InteropMode::Enforce);
    assert_eq!(reg.resolve("injection_control", Some("sqli")), InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", Some("xss")), InteropMode::Enforce);
}

#[test]
fn snapshot_reflects_overrides() {
    let reg = ModeRegistry::new();
    reg.set_feature("bot_detection", InteropMode::LogOnly);
    let snap = reg.snapshot();
    assert_eq!(snap.feature_overrides.get("bot_detection"), Some(&InteropMode::LogOnly));
}

#[test]
fn interop_mode_contract_strings() {
    assert_eq!(InteropMode::Enforce.as_contract_str(), "enforce");
    assert_eq!(InteropMode::LogOnly.as_contract_str(), "log_only");
    assert_eq!(InteropMode::from_contract_str("enforce"), Some(InteropMode::Enforce));
    assert_eq!(InteropMode::from_contract_str("log_only"), Some(InteropMode::LogOnly));
    assert_eq!(InteropMode::from_contract_str("invalid"), None);
}

#[test]
fn interop_mode_serde_roundtrip() {
    let enforce_json = serde_json::to_string(&InteropMode::Enforce).unwrap();
    let log_only_json = serde_json::to_string(&InteropMode::LogOnly).unwrap();
    assert_eq!(enforce_json, "\"enforce\"");
    assert_eq!(log_only_json, "\"log_only\"");

    let e: InteropMode = serde_json::from_str(&enforce_json).unwrap();
    let l: InteropMode = serde_json::from_str(&log_only_json).unwrap();
    assert_eq!(e, InteropMode::Enforce);
    assert_eq!(l, InteropMode::LogOnly);
}

#[test]
fn set_features_batch() {
    let reg = ModeRegistry::new();
    reg.set_features(
        &["injection_control", "rate_limiting", "bot_detection"],
        InteropMode::LogOnly,
    );
    assert_eq!(reg.resolve("injection_control", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("rate_limiting", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("bot_detection", None), InteropMode::LogOnly);
    assert_eq!(reg.resolve("geo_protection", None), InteropMode::Enforce);
}

#[test]
fn set_policies_batch() {
    let reg = ModeRegistry::new();
    reg.set_policies("injection_control", &["sqli", "xss"], InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", Some("sqli")), InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", Some("xss")), InteropMode::LogOnly);
    assert_eq!(reg.resolve("injection_control", Some("rce")), InteropMode::Enforce);
}

#[test]
fn reset_returns_to_defaults() {
    let reg = ModeRegistry::new();
    reg.set_all(InteropMode::LogOnly);
    reg.set_feature("bot_detection", InteropMode::Enforce);
    reg.set_policy("injection_control", "sqli", InteropMode::Enforce);
    reg.reset();
    let snap = reg.snapshot();
    assert_eq!(snap.default_mode, InteropMode::Enforce);
    assert!(snap.feature_overrides.is_empty());
    assert!(snap.policy_overrides.is_empty());
}

#[test]
fn concurrent_access() {
    let reg = Arc::new(ModeRegistry::new());
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let r = Arc::clone(&reg);
            std::thread::spawn(move || {
                for _ in 0..1000 {
                    if i % 2 == 0 {
                        r.set_feature("injection_control", InteropMode::LogOnly);
                    } else {
                        let _ = r.resolve("injection_control", Some("sqli"));
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
}

#[test]
fn mode_state_clone_is_independent() {
    let reg = ModeRegistry::new();
    reg.set_feature("bot_detection", InteropMode::LogOnly);
    let snap = reg.snapshot();

    reg.set_feature("bot_detection", InteropMode::Enforce);
    assert_eq!(
        snap.feature_overrides.get("bot_detection"),
        Some(&InteropMode::LogOnly),
        "snapshot must be independent of subsequent mutations"
    );
}
