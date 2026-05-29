use waf_engine::interop::FeatureCatalog;

#[test]
fn catalog_contains_all_17_features() {
    let cat = FeatureCatalog::all();
    assert_eq!(cat.len(), 17);

    let expected = [
        "access_control",
        "injection_control",
        "path_traversal",
        "network_protection",
        "rate_limiting",
        "ddos_protection",
        "bot_detection",
        "owasp_rules",
        "custom_rules",
        "geo_protection",
        "data_protection",
        "reputation",
        "risk_assessment",
        "velocity_control",
        "device_intelligence",
        "auth_protection",
        "payload_protection",
    ];
    for name in expected {
        assert!(cat.contains_key(name), "missing feature: {name}");
    }
}

#[test]
fn all_features_have_policies_and_are_supported() {
    for (name, info) in FeatureCatalog::all() {
        assert!(!info.policies.is_empty(), "feature {name} has no policies");
        assert!(info.supported, "feature {name} is not supported");
    }
}

#[test]
fn feature_exists_and_policy_exists() {
    assert!(FeatureCatalog::feature_exists("injection_control"));
    assert!(!FeatureCatalog::feature_exists("nonexistent"));
    assert!(FeatureCatalog::policy_exists("injection_control", "sqli"));
    assert!(!FeatureCatalog::policy_exists("injection_control", "nonexistent"));
    assert!(!FeatureCatalog::policy_exists("nonexistent", "sqli"));
}

#[test]
fn validate_features_splits_supported_and_unsupported() {
    let input = vec![
        "injection_control".to_owned(),
        "rate_limiting".to_owned(),
        "made_up_feature".to_owned(),
    ];
    let (supported, unsupported) = FeatureCatalog::validate_features(&input);
    assert_eq!(supported, vec!["injection_control", "rate_limiting"]);
    assert_eq!(unsupported, vec!["made_up_feature"]);
}

#[test]
fn validate_policies_splits_known_and_unknown() {
    let input = vec!["sqli".to_owned(), "xss".to_owned(), "fake_policy".to_owned()];
    let (known, unknown) = FeatureCatalog::validate_policies("injection_control", &input);
    assert_eq!(known, vec!["sqli", "xss"]);
    assert_eq!(unknown, vec!["fake_policy"]);
}

#[test]
fn validate_policies_for_unknown_feature_returns_all_unsupported() {
    let input = vec!["sqli".to_owned()];
    let (known, unknown) = FeatureCatalog::validate_policies("nonexistent", &input);
    assert!(known.is_empty());
    assert_eq!(unknown, vec!["sqli"]);
}

#[test]
fn specific_feature_policies() {
    let cat = FeatureCatalog::all();

    let ac = &cat["access_control"];
    assert_eq!(
        ac.policies,
        vec!["ip_whitelist", "ip_blacklist", "url_whitelist", "url_blacklist"]
    );

    let ic = &cat["injection_control"];
    assert_eq!(ic.policies, vec!["sqli", "xss", "rce"]);

    let cr = &cat["custom_rules"];
    assert_eq!(cr.policies, vec!["yaml_rules", "rhai_scripts", "wasm_plugins"]);
}

#[test]
fn feature_info_toggleable() {
    let cat = FeatureCatalog::all();
    for (_name, info) in &cat {
        assert!(info.toggleable, "all features should be toggleable");
    }
}
