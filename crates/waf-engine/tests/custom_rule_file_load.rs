//! FR-003 phase-02 acceptance — exercises the file-based custom rule loader
//! end-to-end: parse YAML from a tempdir, feed into `CustomRulesEngine`,
//! verify a matching `RequestCtx` triggers a detection.
//!
//! We bypass `WafEngine::reload_rules` (which needs a real `Database`) because
//! the loader is the unit under test — the `WafEngine` wiring just calls
//! `add_rule` per result, which is already covered by other engine tests.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use bytes::Bytes;
use tempfile::tempdir;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::CustomRulesEngine;
use waf_engine::rules::custom_file_loader::load_dir;

fn ctx_for(host_code: &str, path: &str) -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: host_code.into(),
        host: "example.com".into(),
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "fr003-load".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 12345,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: path.into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
    }
}

/// AC-1 — a `kind: custom_rule_v1` YAML produces a rule that matches a request.
#[test]
fn ac1_yaml_rule_matches_request() {
    let tmp = tempdir().unwrap();
    let custom = tmp.path().join("custom");
    fs::create_dir_all(&custom).unwrap();
    fs::write(
        custom.join("block-admin.yaml"),
        r"
kind: custom_rule_v1
id: r-admin
host_code: test
name: Block /admin
conditions:
  - field: path
    operator: starts_with
    value: /admin
",
    )
    .unwrap();

    let rules = load_dir(tmp.path()).unwrap();
    assert_eq!(rules.len(), 1);

    let engine = CustomRulesEngine::new();
    for rule in rules {
        engine.add_rule(rule);
    }

    let hit = engine.check(&ctx_for("test", "/admin/users")).expect("should match");
    assert_eq!(hit.rule_id.as_deref(), Some("r-admin"));

    assert!(engine.check(&ctx_for("test", "/public")).is_none());
}

/// AC-2 — legacy YAML without a `kind` discriminator yields zero custom rules
/// and does not error.
#[test]
fn ac2_legacy_yaml_without_kind_is_skipped() {
    let tmp = tempdir().unwrap();
    let custom = tmp.path().join("custom");
    fs::create_dir_all(&custom).unwrap();
    // Registry-format YAML — top-level sequence, no `kind`.
    fs::write(
        custom.join("legacy.yaml"),
        "- id: TEST-001\n  name: legacy registry rule\n",
    )
    .unwrap();

    let rules = load_dir(tmp.path()).unwrap();
    assert!(rules.is_empty(), "legacy yaml must produce zero custom rules");
}

/// AC-5 — host-scoped + global rules from separate files coexist and route
/// to their respective hosts.
#[test]
fn ac5_global_and_host_specific_rules_route_correctly() {
    let tmp = tempdir().unwrap();
    let custom = tmp.path().join("custom");
    fs::create_dir_all(&custom).unwrap();

    // Global rule (host_code "*") — fires for any host.
    fs::write(
        custom.join("global.yaml"),
        r#"
kind: custom_rule_v1
id: r-global
host_code: "*"
name: Global block /evil
conditions:
  - field: path
    operator: eq
    value: /evil
"#,
    )
    .unwrap();

    // Host-specific rule for "myapp".
    fs::write(
        custom.join("myapp.yaml"),
        r"
kind: custom_rule_v1
id: r-myapp
host_code: myapp
name: myapp block /private
conditions:
  - field: path
    operator: eq
    value: /private
",
    )
    .unwrap();

    let rules = load_dir(tmp.path()).unwrap();
    assert_eq!(rules.len(), 2);

    let engine = CustomRulesEngine::new();
    for rule in rules {
        engine.add_rule(rule);
    }

    // Global rule fires regardless of host_code.
    let any_host = engine.check(&ctx_for("anything", "/evil")).expect("global hit");
    assert_eq!(any_host.rule_id.as_deref(), Some("r-global"));

    // Host-specific rule fires only for matching host_code.
    let myapp = engine.check(&ctx_for("myapp", "/private")).expect("myapp hit");
    assert_eq!(myapp.rule_id.as_deref(), Some("r-myapp"));

    // Same path on a different host_code → no host-specific match (and global
    // rule keys on path "/evil", not "/private") → None.
    assert!(engine.check(&ctx_for("other", "/private")).is_none());
}
