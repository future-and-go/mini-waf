use std::collections::HashMap;

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct FeatureInfo {
    pub supported: bool,
    pub toggleable: bool,
    pub policies: Vec<&'static str>,
}

pub struct FeatureCatalog;

impl FeatureCatalog {
    pub fn all() -> HashMap<&'static str, FeatureInfo> {
        let entries: Vec<(&str, &[&str])> = vec![
            (
                "access_control",
                &["ip_whitelist", "ip_blacklist", "url_whitelist", "url_blacklist"],
            ),
            ("injection_control", &["sqli", "xss", "rce"]),
            ("path_traversal", &["dir_traversal"]),
            ("network_protection", &["ssrf", "header_injection"]),
            ("rate_limiting", &["per_ip", "per_session"]),
            ("ddos_protection", &["per_ip_burst", "per_tier"]),
            ("bot_detection", &["scanner", "bot"]),
            ("owasp_rules", &["core_ruleset"]),
            ("custom_rules", &["yaml_rules", "rhai_scripts", "wasm_plugins"]),
            ("geo_protection", &["geo_blocking"]),
            ("data_protection", &["sensitive_data", "anti_hotlink"]),
            ("reputation", &["crowdsec", "community_blocklist"]),
            ("risk_assessment", &["cumulative_risk"]),
            ("velocity_control", &["tx_velocity"]),
            ("device_intelligence", &["fingerprint_analysis"]),
            ("auth_protection", &["brute_force"]),
            ("payload_protection", &["body_abuse"]),
        ];

        entries
            .into_iter()
            .map(|(name, policies)| {
                let info = FeatureInfo {
                    supported: true,
                    toggleable: true,
                    policies: policies.to_vec(),
                };
                (name, info)
            })
            .collect()
    }

    pub fn feature_exists(name: &str) -> bool {
        Self::all().contains_key(name)
    }

    pub fn policy_exists(feature: &str, policy: &str) -> bool {
        Self::all()
            .get(feature)
            .is_some_and(|info| info.policies.contains(&policy))
    }

    /// Split feature names into (supported, unsupported).
    pub fn validate_features(names: &[String]) -> (Vec<String>, Vec<String>) {
        let catalog = Self::all();
        let mut supported = Vec::new();
        let mut unsupported = Vec::new();
        for name in names {
            if catalog.contains_key(name.as_str()) {
                supported.push(name.clone());
            } else {
                unsupported.push(name.clone());
            }
        }
        (supported, unsupported)
    }

    /// Split policy names into (known, unknown) for a given feature.
    pub fn validate_policies(feature: &str, names: &[String]) -> (Vec<String>, Vec<String>) {
        let catalog = Self::all();
        let mut known = Vec::new();
        let mut unknown = Vec::new();

        match catalog.get(feature) {
            Some(info) => {
                for name in names {
                    if info.policies.contains(&name.as_str()) {
                        known.push(name.clone());
                    } else {
                        unknown.push(name.clone());
                    }
                }
            }
            None => {
                unknown.extend(names.iter().cloned());
            }
        }

        (known, unknown)
    }
}
