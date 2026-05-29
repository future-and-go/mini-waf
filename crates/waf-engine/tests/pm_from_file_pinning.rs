//! Pinning tests for the `pm_from_file` / `contains_any` silent-fail bug.
//!
//! Phase 1 of the pm_from_file matcher-unification refactor (see
//! `plans/260524-2041-pm-from-file-matcher-fix/`).
//!
//! These tests MUST FAIL on `main`. They pin the live bug:
//! `pm_from_file` and `contains_any` operators are routed by the YAML parser
//! into `CustomRule.specialised_op`, but `CustomRulesEngine::eval_specialised`
//! only implements `DetectSqli` / `DetectXss` — the other two fall into a
//! silent `_ => false` arm. As a result, CRS-930130 (`/.env` block) is
//! `enabled: true, action: block` in YAML but inert at runtime.
//!
//! After Phase 2 unifies the dispatch into `Matcher`, these MUST turn green.
//! Do not mark them `#[ignore]` — the deliberate red on `main` is the gate.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::doc_markdown
)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::CustomRulesEngine;
use waf_engine::OWASPCheck;
use waf_engine::checks::Check;
use waf_engine::rules::formats::custom_rule_yaml;

// ── Fixture ─────────────────────────────────────────────────────────────────

/// Path to the real `rules/owasp-crs/` directory at the repo root.
fn crs_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("workspace root")
        .join("rules")
        .join("owasp-crs")
}

/// Load OWASP CRS rules using the production directory walker.
fn load_crs_engine() -> OWASPCheck {
    let dir = crs_rules_dir();
    assert!(dir.is_dir(), "expected CRS dir at {} — fixture missing", dir.display());
    let checker = OWASPCheck::from_directory(&dir);
    assert!(
        checker.rule_count() > 0,
        "OWASPCheck loaded zero rules from {}",
        dir.display()
    );
    checker
}

fn ctx_with(method: &str, path: &str, query: &str, body: &[u8], headers: &[(&str, &str)]) -> RequestCtx {
    let mut hdrs = HashMap::new();
    for (k, v) in headers {
        hdrs.insert((*k).to_ascii_lowercase(), (*v).to_string());
    }
    let host_config = Arc::new(HostConfig {
        code: "test".into(),
        host: "example.com".into(),
        defense_config: waf_common::DefenseConfig {
            owasp_set: true,
            owasp_paranoia: 4,
            ..Default::default()
        },
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "pin".into(),
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
    }
}

// ── pm_from_file pinning (CRS-930130 restricted-files.data) ─────────────────

#[test]
fn pin_dotenv_path_must_block() {
    let checker = load_crs_engine();
    let ctx = ctx_with("GET", "/.env", "", &[], &[]);
    let result = checker.check(&ctx);
    assert!(
        result.is_some(),
        "BUG: GET /.env must be blocked by CRS-930130 (restricted-files.data) — \
         currently silent-fails because pm_from_file routes through eval_specialised"
    );
}

#[test]
fn pin_dotenvrc_path_must_block() {
    let checker = load_crs_engine();
    let ctx = ctx_with("GET", "/.envrc", "", &[], &[]);
    assert!(
        checker.check(&ctx).is_some(),
        "BUG: GET /.envrc must be blocked by CRS-930130"
    );
}

#[test]
fn pin_dotenv_uppercase_must_block_case_insensitive() {
    let checker = load_crs_engine();
    let ctx = ctx_with("GET", "/.ENV", "", &[], &[]);
    assert!(
        checker.check(&ctx).is_some(),
        "BUG: GET /.ENV must be blocked — pm_from_file must be case-insensitive"
    );
}

#[test]
fn pin_dotenv_url_encoded_must_block() {
    let checker = load_crs_engine();
    // %2E == '.' — must be decoded before pattern match.
    let ctx = ctx_with("GET", "/%2Eenv", "", &[], &[]);
    assert!(
        checker.check(&ctx).is_some(),
        "BUG: GET /%2Eenv must be blocked — pm_from_file must URL-decode the path"
    );
}

#[test]
fn pin_htpasswd_in_subpath_must_block() {
    let checker = load_crs_engine();
    let ctx = ctx_with("GET", "/path/with/.htpasswd", "", &[], &[]);
    assert!(
        checker.check(&ctx).is_some(),
        "BUG: GET /path/with/.htpasswd must be blocked by CRS-930130"
    );
}

// ── pm_from_file pinning (CRS-930120 lfi-os-files.data) ─────────────────────

#[test]
fn pin_lfi_os_file_in_body_must_block() {
    // CRS-930120 default pattern_field=body; `config.ini` is listed in
    // lfi-os-files.data and is NOT matched by dir_traversal regex or
    // other CRS rules — so a hit here proves pm_from_file is wired.
    let checker = load_crs_engine();
    let body = b"file=config.ini";
    let ctx = ctx_with("POST", "/include", "", body, &[]);
    assert!(
        checker.check(&ctx).is_some(),
        "BUG: body containing 'config.ini' must be blocked by CRS-930120 (lfi-os-files.data) — \
         currently silent-fails because pm_from_file routes through eval_specialised"
    );
}

// ── pm_from_file negative case ──────────────────────────────────────────────

#[test]
fn pin_innocuous_path_must_pass() {
    let checker = load_crs_engine();
    let ctx = ctx_with("GET", "/users/profile", "", &[], &[("accept", "*/*")]);
    // No CRS rule should match a benign request — guards against
    // false-positive over-matching after the matcher unification.
    assert!(
        checker.check(&ctx).is_none(),
        "innocuous GET /users/profile must not match any CRS rule"
    );
}

// ── contains_any pinning (isolated single-rule fixtures) ────────────────────
//
// CRS-loaded fixtures can incidentally match other regex rules and mask the
// bug. These tests load ONLY the contains_any rule through the same YAML
// parser the production loader uses (`custom_rule_yaml::parse` →
// `engine.add_rule`), so a green here means contains_any itself is wired.

/// Load a single rule from inline YAML through the production parser.
fn engine_from_yaml(yaml: &str) -> CustomRulesEngine {
    let engine = CustomRulesEngine::new();
    let rules = custom_rule_yaml::parse(yaml).expect("YAML must parse");
    assert!(!rules.is_empty(), "fixture must produce at least one rule");
    for rule in rules {
        engine.add_rule(rule);
    }
    engine
}

const XSS_CONTAINS_ANY_RULE: &str = r#"
kind: custom_rule_v1
id: PIN-XSS-CONTAINS-ANY
name: pinned contains_any xss
enabled: true
action: block
pattern_field: all
operator: contains_any
value: "document.cookie -moz-binding <![cdata["
category: xss
severity: critical
paranoia: 1
"#;

#[test]
fn pin_contains_any_xss_payload_must_block() {
    // Mirrors the CRS-941180 contains_any operator. With the bug present the
    // engine silently returns None because contains_any falls through
    // eval_specialised's catch-all arm.
    let engine = engine_from_yaml(XSS_CONTAINS_ANY_RULE);
    let ctx = ctx_with("GET", "/", "q=document.cookie", &[], &[]);
    assert!(
        engine.check(&ctx).is_some(),
        "BUG: contains_any payload 'document.cookie' must be detected — \
         currently silent-fails because contains_any routes through eval_specialised"
    );
}

const PHP_CONTAINS_ANY_RULE: &str = r#"
kind: custom_rule_v1
id: PIN-PHP-CONTAINS-ANY
name: pinned contains_any php-close-tag
enabled: true
action: block
pattern_field: all
operator: contains_any
value: "?>"
category: php-injection
severity: critical
paranoia: 1
"#;

#[test]
fn pin_contains_any_php_close_tag_must_block() {
    // Mirrors CRS-933190 contains_any value `?>`. Isolated single-rule fixture.
    let engine = engine_from_yaml(PHP_CONTAINS_ANY_RULE);
    let body = b"comment=hello?>evil";
    let ctx = ctx_with("POST", "/comment", "", body, &[]);
    assert!(
        engine.check(&ctx).is_some(),
        "BUG: contains_any payload '?>' must be detected — \
         currently silent-fails because contains_any routes through eval_specialised"
    );
}
