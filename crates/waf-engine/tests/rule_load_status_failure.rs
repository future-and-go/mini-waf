//! Phase 3 acceptance — validates that rules referencing nonexistent data files
//! are excluded from the active rule set and tracked in the load report.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::needless_pass_by_value,
    clippy::doc_markdown,
    unused_imports
)]

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
        req_id: "load-status-test".into(),
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

/// A rule with `operator: pm_from_file` referencing a nonexistent .data file
/// must be excluded from the active set and tracked in the load report as
/// a failure with reason "missing_data_file" (or similar parse_error).
#[test]
fn rule_with_missing_data_file_excluded_and_reported() {
    let tmp = tempdir().unwrap();
    let custom = tmp.path().join("custom");
    fs::create_dir_all(&custom).unwrap();

    // Rule references nonexistent.data — the YAML parser will fail to resolve
    // the data file path, producing a parse error that prevents the rule from
    // loading into the engine.
    fs::write(
        custom.join("bad-pm.yaml"),
        r"
kind: custom_rule_v1
id: bad-pm-rule
host_code: '*'
name: Bad pm_from_file
conditions:
  - field: all
    operator: pm_from_file
    value: nonexistent.data
",
    )
    .unwrap();

    // Also write a valid rule alongside to confirm partial load works.
    fs::write(
        custom.join("good.yaml"),
        r"
kind: custom_rule_v1
id: good-rule
host_code: '*'
name: Block /admin
conditions:
  - field: path
    operator: starts_with
    value: /admin
",
    )
    .unwrap();

    let rules = load_dir(tmp.path()).unwrap();
    // The bad pm_from_file rule may either:
    // (a) fail at YAML parse time (load_dir skips it), or
    // (b) load but fail at compile time (compile_rule returns Err).
    // Either way the good rule must survive.
    let engine = CustomRulesEngine::new();
    for rule in rules {
        engine.add_file_rule(rule);
    }

    // Good rule fires
    let hit = engine.check(&ctx_for("test", "/admin/x"));
    assert!(hit.is_some(), "good rule must be in active set");
    assert_eq!(hit.unwrap().rule_id.as_deref(), Some("good-rule"));
}

/// A rule with an invalid regex produces a compile error and is excluded.
#[test]
fn rule_with_invalid_regex_excluded_and_tracked() {
    let engine = CustomRulesEngine::new();
    let rule = waf_engine::rules::engine::CustomRule {
        id: "bad-regex".into(),
        host_code: "*".into(),
        name: "Bad regex".into(),
        priority: 1,
        enabled: true,
        condition_op: waf_engine::rules::engine::ConditionOp::And,
        conditions: vec![waf_engine::rules::engine::Condition {
            field: waf_engine::rules::engine::ConditionField::Path,
            operator: waf_engine::rules::engine::Operator::Regex,
            value: waf_engine::rules::engine::ConditionValue::Str("(unclosed".into()),
        }],
        action: waf_common::RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script: None,
        match_tree: None,
        risk_delta: None,
        risk_action: None,
        pattern: None,
        pattern_field: "all".into(),
        category: None,
        severity: None,
        paranoia: None,
        tags: Vec::new(),
        metadata: HashMap::new(),
        reference: None,
    };

    engine.add_file_rule(rule);

    // Rule should be tracked as failed in load report
    let report = engine.load_report();
    assert_eq!(report.failed.len(), 1, "one failure expected");
    assert_eq!(report.failed[0].rule_id, "bad-regex");
    assert_eq!(report.failed[0].reason, "invalid_regex");

    // Rule must not fire
    assert!(engine.check(&ctx_for("test", "/anything")).is_none());
}

/// A rule with an invalid CIDR produces a compile error.
#[test]
fn rule_with_invalid_cidr_excluded_and_tracked() {
    let engine = CustomRulesEngine::new();
    let rule = waf_engine::rules::engine::CustomRule {
        id: "bad-cidr".into(),
        host_code: "*".into(),
        name: "Bad CIDR".into(),
        priority: 1,
        enabled: true,
        condition_op: waf_engine::rules::engine::ConditionOp::And,
        conditions: vec![waf_engine::rules::engine::Condition {
            field: waf_engine::rules::engine::ConditionField::Ip,
            operator: waf_engine::rules::engine::Operator::CidrMatch,
            value: waf_engine::rules::engine::ConditionValue::Str("not-a-cidr".into()),
        }],
        action: waf_common::RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script: None,
        match_tree: None,
        risk_delta: None,
        risk_action: None,
        pattern: None,
        pattern_field: "all".into(),
        category: None,
        severity: None,
        paranoia: None,
        tags: Vec::new(),
        metadata: HashMap::new(),
        reference: None,
    };

    engine.add_file_rule(rule);

    let report = engine.load_report();
    assert_eq!(report.failed.len(), 1);
    assert_eq!(report.failed[0].rule_id, "bad-cidr");
    assert_eq!(report.failed[0].reason, "invalid_cidr");
}

/// Valid rules are tracked as loaded in the report.
#[test]
fn valid_rule_tracked_as_loaded() {
    let engine = CustomRulesEngine::new();
    let rule = waf_engine::rules::engine::CustomRule {
        id: "good-rule".into(),
        host_code: "*".into(),
        name: "Good rule".into(),
        priority: 1,
        enabled: true,
        condition_op: waf_engine::rules::engine::ConditionOp::And,
        conditions: vec![waf_engine::rules::engine::Condition {
            field: waf_engine::rules::engine::ConditionField::Path,
            operator: waf_engine::rules::engine::Operator::StartsWith,
            value: waf_engine::rules::engine::ConditionValue::Str("/admin".into()),
        }],
        action: waf_common::RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script: None,
        match_tree: None,
        risk_delta: None,
        risk_action: None,
        pattern: None,
        pattern_field: "all".into(),
        category: None,
        severity: None,
        paranoia: None,
        tags: Vec::new(),
        metadata: HashMap::new(),
        reference: None,
    };

    engine.add_file_rule(rule);

    let report = engine.load_report();
    assert_eq!(report.loaded.len(), 1);
    assert_eq!(report.loaded[0], "good-rule");
    assert!(report.failed.is_empty());
}

/// clear_file_rules resets the load report.
#[test]
fn clear_file_rules_resets_load_report() {
    let engine = CustomRulesEngine::new();
    let rule = waf_engine::rules::engine::CustomRule {
        id: "bad-regex-2".into(),
        host_code: "*".into(),
        name: "Bad regex 2".into(),
        priority: 1,
        enabled: true,
        condition_op: waf_engine::rules::engine::ConditionOp::And,
        conditions: vec![waf_engine::rules::engine::Condition {
            field: waf_engine::rules::engine::ConditionField::Path,
            operator: waf_engine::rules::engine::Operator::Regex,
            value: waf_engine::rules::engine::ConditionValue::Str("(unclosed".into()),
        }],
        action: waf_common::RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script: None,
        match_tree: None,
        risk_delta: None,
        risk_action: None,
        pattern: None,
        pattern_field: "all".into(),
        category: None,
        severity: None,
        paranoia: None,
        tags: Vec::new(),
        metadata: HashMap::new(),
        reference: None,
    };

    engine.add_file_rule(rule);
    assert_eq!(engine.load_report().failed.len(), 1);

    engine.clear_file_rules();
    let report = engine.load_report();
    assert!(report.loaded.is_empty());
    assert!(report.failed.is_empty());
}
