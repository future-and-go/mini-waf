//! OWASP rule equivalence tests: verify the unified CustomRulesEngine
//! detects known attack patterns (SQLi, SSTI, SSRF) after YAML migration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::CustomRulesEngine;
use waf_engine::rules::formats::custom_rule_yaml;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rules")
}

fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in fs::read_dir(dir).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_yaml_files(&path));
        } else if path.extension().and_then(|s| s.to_str()) == Some("yaml") {
            files.push(path);
        }
    }
    files
}

fn build_test_engine() -> CustomRulesEngine {
    build_engine_from_dirs(&["advanced", "owasp-crs"])
}

/// Load rules from specific subdirectories under `rules/`.
/// Parses per-document so oversized regexes in one rule don't skip the whole file.
fn build_engine_from_dirs(subdirs: &[&str]) -> CustomRulesEngine {
    let engine = CustomRulesEngine::new();
    let root = rules_dir();
    for subdir in subdirs {
        let dir = root.join(subdir);
        for path in collect_yaml_files(&dir) {
            let content = fs::read_to_string(&path).unwrap_or_default();
            for doc_text in content.split("---") {
                let trimmed = doc_text.trim();
                if trimmed.is_empty() || !trimmed.contains("kind: custom_rule_v1") {
                    continue;
                }
                let doc = format!("---\n{trimmed}");
                if let Ok(rules) = custom_rule_yaml::parse(&doc) {
                    for rule in rules {
                        engine.add_rule(rule);
                    }
                }
            }
        }
    }
    engine
}

fn default_host_config() -> Arc<HostConfig> {
    Arc::new(HostConfig {
        code: "*".into(),
        host: "example.com".into(),
        ..HostConfig::default()
    })
}

fn ctx_with_query(query: &str) -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert("accept".into(), "*/*".into());
    RequestCtx {
        req_id: "owasp-eq".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 12345,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: "/search".into(),
        query: query.into(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: default_host_config(),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
    }
}

fn ctx_with_body(body: &str) -> RequestCtx {
    let body_bytes = Bytes::from(body.to_string());
    let mut headers = HashMap::new();
    headers.insert("accept".into(), "*/*".into());
    RequestCtx {
        req_id: "owasp-eq".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 12345,
        method: "POST".into(),
        host: "example.com".into(),
        port: 80,
        path: "/api/submit".into(),
        query: String::new(),
        headers,
        body_preview: body_bytes.clone(),
        content_length: body_bytes.len() as u64,
        is_tls: false,
        host_config: default_host_config(),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
    }
}

fn ctx_with_host_header(host: &str) -> RequestCtx {
    let mut headers = HashMap::new();
    headers.insert("user-agent".into(), "Mozilla/5.0 TestBrowser".into());
    headers.insert("accept".into(), "*/*".into());
    RequestCtx {
        req_id: "owasp-eq".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 12345,
        method: "GET".into(),
        host: host.into(),
        port: 80,
        path: "/".into(),
        query: String::new(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: default_host_config(),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
    }
}

// ── SQLi detection ───────────────────────────────────────────────────────────

#[test]
fn detects_sqli_union_select() {
    let engine = build_test_engine();
    let ctx = ctx_with_query("id=1 UNION SELECT * FROM users--");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SQLi UNION SELECT should be detected");
}

#[test]
fn detects_sqli_in_body() {
    let engine = build_test_engine();
    let ctx = ctx_with_body("username=admin' OR 1=1--&password=x");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SQLi in POST body should be detected");
}

// ── SSTI detection ───────────────────────────────────────────────────────────

#[test]
fn detects_ssti_template_injection() {
    let engine = build_test_engine();
    let ctx = ctx_with_body("name={{7*7}}");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SSTI {{7*7}} should be detected");
}

#[test]
fn detects_ssti_dollar_brace() {
    let engine = build_test_engine();
    let ctx = ctx_with_query("input=${7*7}");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SSTI ${{7*7}} should be detected");
}

// ── SSRF detection ───────────────────────────────────────────────────────────

#[test]
fn detects_ssrf_link_local() {
    let engine = build_test_engine();
    let ctx = ctx_with_body("url=http://169.254.169.254/latest/meta-data/");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(
        verdict.result.is_some(),
        "SSRF to link-local 169.254.x.x should be detected"
    );
}

#[test]
fn detects_ssrf_rfc1918() {
    let engine = build_test_engine();
    let ctx = ctx_with_body("target=http://10.0.0.1/admin");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SSRF to RFC1918 10.x.x.x should be detected");
}

// ── URL-decode bypass ────────────────────────────────────────────────────────

#[test]
fn url_decode_bypass_detected() {
    let engine = build_test_engine();
    // %7B%7B7*7%7D%7D == {{7*7}}
    let ctx = ctx_with_query("name=%7B%7B7*7%7D%7D");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(
        verdict.result.is_some(),
        "URL-encoded SSTI should be detected via decode bypass protection"
    );
}

// ── XSS detection ────────────────────────────────────────────────────────────

#[test]
fn detects_xss_script_tag() {
    let engine = build_test_engine();
    let ctx = ctx_with_query("q=<script>alert(1)</script>");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "XSS script tag should be detected");
}

// ── RCE detection ────────────────────────────────────────────────────────────

#[test]
fn detects_rce_command_injection() {
    let engine = build_test_engine();
    let ctx = ctx_with_body("cmd=;cat /etc/passwd");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "RCE command injection should be detected");
}

// ── Routing header exclusion ─────────────────────────────────────────────────

#[test]
fn host_header_does_not_trigger_ssrf_rules() {
    let engine = build_test_engine();
    // "localhost" in Host header should NOT trigger SSRF rules because
    // the engine excludes routing headers (host, authority, etc.) from
    // the "all" field scan.
    let ctx = ctx_with_host_header("localhost:8080");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(
        verdict.result.is_none(),
        "Host header 'localhost' should not trigger SSRF rules, \
         but got: {:?}",
        verdict.result
    );
}

// ── Paranoia filtering ───────────────────────────────────────────────────────

#[test]
fn paranoia_filtering_respects_level() {
    let engine = build_test_engine();
    let ctx = ctx_with_query("test=normal-input");

    // Paranoia 1: only stable, low-FP rules
    let result_p1 = engine.check_owasp(&ctx, 1);
    // Paranoia 4: all rules including aggressive ones
    let result_p4 = engine.check_owasp(&ctx, 4);

    // For benign input, neither should trigger. The key property:
    // if p1 triggers, p4 must also trigger (superset guarantee).
    if result_p1.is_some() {
        assert!(result_p4.is_some(), "Paranoia 4 must be a superset of paranoia 1");
    }
}

#[test]
fn paranoia_2_detects_boolean_sqli_not_caught_at_1() {
    let engine = build_test_engine();
    // `sort=name` looks like `identifier=identifier` — triggers CRS-942130
    // (paranoia 2) but not paranoia-1 rules.
    let ctx = ctx_with_query("sort=name");
    let result_p1 = engine.check_owasp(&ctx, 1);
    let result_p2 = engine.check_owasp(&ctx, 2);

    assert!(result_p1.is_none(), "Paranoia 1 should not flag benign key=value");
    assert!(
        result_p2.is_some(),
        "Paranoia 2 should detect boolean-style SQLi in key=value"
    );
}

#[test]
fn owasp_check_detects_sqli_at_paranoia_1() {
    let engine = build_test_engine();
    let ctx = ctx_with_query("id=1 UNION SELECT * FROM users--");
    let result = engine.check_owasp(&ctx, 1);
    assert!(result.is_some(), "OWASP check at paranoia 1 should detect obvious SQLi");
}

// ── Clean traffic (false-positive guard) ─────────────────────────────────────

#[test]
fn clean_request_without_query_not_blocked() {
    let engine = build_test_engine();
    let mut headers = HashMap::new();
    headers.insert("user-agent".into(), "Mozilla/5.0 TestBrowser".into());
    headers.insert("accept".into(), "*/*".into());
    let ctx = RequestCtx {
        req_id: "owasp-eq".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 12345,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: "/products".into(),
        query: String::new(),
        headers,
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: default_host_config(),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
    };
    let verdict = engine.check_with_verdict(&ctx);
    assert!(
        verdict.result.is_none(),
        "Clean GET without query should not trigger any rules, \
         but got: {:?}",
        verdict.result
    );
}
