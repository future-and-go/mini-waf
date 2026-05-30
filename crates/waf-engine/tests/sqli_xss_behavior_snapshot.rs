//! Snapshot of current `detect_sqli` / `detect_xss` behaviour (Phase 1 of
//! pm_from_file matcher-unification refactor).
//!
//! Each case mirrors a row from `crates/waf-engine/src/checks/owasp.rs` unit
//! tests, but loads rules via the production `custom_rule_v1` YAML parser and
//! evaluates through `CustomRulesEngine` so the YAML→Condition→Matcher
//! dispatch is fully exercised. After Phase 2 deletes `eval_specialised`, this
//! file's tests MUST stay green — they are the gate against behavioural drift
//! when libinjection moves into the generic `Matcher::matches` path.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::CustomRulesEngine;
use waf_engine::rules::formats::custom_rule_yaml;

// ── Fixtures ────────────────────────────────────────────────────────────────

const SQLI_ALL_FIELD: &str = r#"
kind: custom_rule_v1
id: SNAP-SQLI-ALL
name: SQLi all fields
enabled: true
action: block
pattern_field: all
operator: detect_sqli
value: ""
category: sqli
severity: critical
paranoia: 1
"#;

const SQLI_QUERY_FIELD: &str = r#"
kind: custom_rule_v1
id: SNAP-SQLI-QUERY
name: SQLi query only
enabled: true
action: block
pattern_field: query
operator: detect_sqli
value: ""
category: sqli
severity: critical
paranoia: 1
"#;

const XSS_ALL_FIELD: &str = r#"
kind: custom_rule_v1
id: SNAP-XSS-ALL
name: XSS all fields
enabled: true
action: block
pattern_field: all
operator: detect_xss
value: ""
category: xss
severity: critical
paranoia: 1
"#;

fn engine_from_yaml(yaml: &str) -> CustomRulesEngine {
    let engine = CustomRulesEngine::new();
    let rules = custom_rule_yaml::parse(yaml).expect("YAML must parse");
    assert!(!rules.is_empty(), "fixture YAML must produce at least one rule");
    for rule in rules {
        engine.add_rule(rule);
    }
    engine
}

fn ctx_with(method: &str, path: &str, query: &str, body: &[u8], headers: &[(&str, &str)]) -> RequestCtx {
    let mut hdrs = HashMap::new();
    for (k, v) in headers {
        hdrs.insert((*k).to_ascii_lowercase(), (*v).to_string());
    }
    let host_config = Arc::new(HostConfig {
        code: "test".into(),
        host: "example.com".into(),
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "snap".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 0,
        method: method.into(),
        host: "example.com".into(),
        port: 80,
        path: path.into(),
        query: query.into(),
        headers: hdrs,
        body_preview: Bytes::copy_from_slice(body),
        content_length: body.len() as u64,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: waf_common::RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
    }
}

// ── detect_sqli snapshots (mirror owasp.rs unit tests) ──────────────────────

#[test]
fn snap_sqli_blocks_or_tautology() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "id=1' OR '1'='1", &[], &[]);
    assert!(engine.check(&ctx).is_some(), "OR tautology must be detected");
}

#[test]
fn snap_sqli_blocks_union_select() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "id=1 UNION SELECT 1,2,3--", &[], &[]);
    assert!(engine.check(&ctx).is_some(), "UNION SELECT must be detected");
}

#[test]
fn snap_sqli_allows_clean_input() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "name=alice&page=2", &[], &[]);
    assert!(engine.check(&ctx).is_none(), "clean query must not match");
}

#[test]
fn snap_sqli_checks_body() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let body = b"username=admin&password=1' OR '1'='1";
    let ctx = ctx_with("POST", "/login", "", body, &[]);
    assert!(engine.check(&ctx).is_some(), "SQLi in body must be detected");
}

#[test]
fn snap_sqli_checks_headers() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "", &[], &[("referer", "http://x/' OR '1'='1")]);
    assert!(engine.check(&ctx).is_some(), "SQLi in referer header must be detected");
}

#[test]
fn snap_sqli_single_field_query_match() {
    let engine = engine_from_yaml(SQLI_QUERY_FIELD);
    let ctx = ctx_with("GET", "/", "id=1' OR '1'='1", &[], &[]);
    assert!(engine.check(&ctx).is_some(), "SQLi in query must be detected");
}

#[test]
fn snap_sqli_single_field_query_skips_path() {
    let engine = engine_from_yaml(SQLI_QUERY_FIELD);
    let ctx = ctx_with("GET", "/1' OR '1'='1", "", &[], &[]);
    assert!(engine.check(&ctx).is_none(), "field=query rule must not inspect path");
}

#[test]
fn snap_sqli_url_encoded_evasion() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    // %27=' %20=space %3D==
    let ctx = ctx_with("GET", "/", "id=1%27%20OR%20%271%27%3D%271", &[], &[]);
    assert!(
        engine.check(&ctx).is_some(),
        "URL-encoded SQLi must be detected after decoding"
    );
}

#[test]
fn snap_sqli_empty_input_safe() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "", &[], &[]);
    assert!(engine.check(&ctx).is_none(), "empty request must not match");
}

#[test]
fn snap_sqli_non_utf8_body_safe() {
    let engine = engine_from_yaml(SQLI_ALL_FIELD);
    let ctx = ctx_with("POST", "/", "", &[0xFF, 0xFE, 0x00, 0x80], &[]);
    assert!(engine.check(&ctx).is_none(), "random binary body must not trigger SQLi");
}

// ── detect_xss snapshots ────────────────────────────────────────────────────

#[test]
fn snap_xss_blocks_script_tag() {
    let engine = engine_from_yaml(XSS_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "q=<script>alert(1)</script>", &[], &[]);
    assert!(engine.check(&ctx).is_some(), "<script> tag must be detected");
}

#[test]
fn snap_xss_blocks_event_handler() {
    let engine = engine_from_yaml(XSS_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "q=<img src=x onerror=alert(1)>", &[], &[]);
    assert!(engine.check(&ctx).is_some(), "onerror handler must be detected");
}

#[test]
fn snap_xss_allows_clean_input() {
    let engine = engine_from_yaml(XSS_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "q=hello+world&page=1", &[], &[]);
    assert!(engine.check(&ctx).is_none(), "clean input must not match XSS");
}

#[test]
fn snap_xss_checks_body() {
    let engine = engine_from_yaml(XSS_ALL_FIELD);
    let body = b"text=<script>alert('xss')</script>";
    let ctx = ctx_with("POST", "/comment", "", body, &[]);
    assert!(engine.check(&ctx).is_some(), "XSS in body must be detected");
}

#[test]
fn snap_xss_url_encoded_evasion() {
    let engine = engine_from_yaml(XSS_ALL_FIELD);
    // %3Cscript%3E = <script>
    let ctx = ctx_with("GET", "/", "q=%3Cscript%3Ealert(1)%3C/script%3E", &[], &[]);
    assert!(
        engine.check(&ctx).is_some(),
        "URL-encoded XSS must be detected after decoding"
    );
}

#[test]
fn snap_xss_empty_input_safe() {
    let engine = engine_from_yaml(XSS_ALL_FIELD);
    let ctx = ctx_with("GET", "/", "", &[], &[]);
    assert!(engine.check(&ctx).is_none(), "empty request must not match XSS");
}
