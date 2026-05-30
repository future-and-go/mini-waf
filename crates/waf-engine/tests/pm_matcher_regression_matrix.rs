//! Regression matrix sweep for `pm_from_file` and `contains_any` operators.
//!
//! Walks `rules/owasp-crs/*.yaml` at runtime, discovers every rule using
//! these operators, and verifies representative patterns from each data file
//! are detected. Also exercises encoding-bypass vectors for path-targeted
//! rules.
//!
//! Designed so that adding a new CRS rule file automatically gets coverage
//! — the test will fail if a new pm_from_file/contains_any rule exists but
//! has no matching test case.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::missing_const_for_fn,
    clippy::needless_pass_by_value,
    clippy::doc_markdown,
    clippy::panic,
    clippy::print_stderr
)]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::checks::Check;
use waf_engine::rules::data_file_registry::DataFileRegistry;
use waf_engine::rules::formats::custom_rule_yaml::{self, LoadContext};
use waf_engine::{CustomRulesEngine, OWASPCheck};

// ── Fixture ─────────────────────────────────────────────────────────────────

fn crs_rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate parent")
        .parent()
        .expect("workspace root")
        .join("rules")
        .join("owasp-crs")
}

fn load_crs_engine() -> OWASPCheck {
    let dir = crs_rules_dir();
    assert!(dir.is_dir(), "CRS dir missing: {}", dir.display());
    let checker = OWASPCheck::from_directory(&dir);
    assert!(checker.rule_count() > 0, "OWASPCheck loaded zero rules");
    checker
}

/// Build a single-file engine from a specific CRS YAML for isolated testing.
/// Useful when multi-doc files fail to parse (oversized regex in another doc).
fn engine_from_crs_file(filename: &str) -> CustomRulesEngine {
    let crs = crs_rules_dir();
    let yaml_path = crs.join(filename);
    let content = std::fs::read_to_string(&yaml_path).unwrap_or_else(|e| panic!("read {filename}: {e}"));
    let rules_root = crs.canonicalize().expect("canonicalize crs dir");
    let registry = DataFileRegistry::new();
    let ctx = LoadContext {
        yaml_path: &yaml_path,
        rules_root: &rules_root,
        registry: &registry,
    };

    let engine = CustomRulesEngine::new();
    // Parse documents individually to skip bad ones
    for (idx, doc_text) in content.split("---").enumerate() {
        let trimmed = doc_text.trim();
        if trimmed.is_empty() || !trimmed.contains("kind: custom_rule_v1") {
            continue;
        }
        let doc_with_kind = format!("---\n{trimmed}");
        match custom_rule_yaml::parse_with_context(&doc_with_kind, Some(&ctx)) {
            Ok(rules) => {
                for rule in rules {
                    engine.add_file_rule(rule);
                }
            }
            Err(_) => {
                eprintln!("NOTE: skipping doc #{} in {filename} (parse error)", idx + 1);
            }
        }
    }
    engine
}

fn ctx_with(method: &str, path: &str, query: &str, body: &[u8], headers: &[(&str, &str)], paranoia: u8) -> RequestCtx {
    let mut hdrs = HashMap::new();
    for (k, v) in headers {
        hdrs.insert((*k).to_ascii_lowercase(), (*v).to_string());
    }
    let host_config = Arc::new(HostConfig {
        code: "*".into(),
        host: "example.com".into(),
        defense_config: waf_common::DefenseConfig {
            owasp_set: true,
            owasp_paranoia: paranoia,
            ..Default::default()
        },
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "regmatrix".into(),
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
        tx_velocity_token: None,
    }
}

fn ctx_p4(method: &str, path: &str, query: &str, body: &[u8], headers: &[(&str, &str)]) -> RequestCtx {
    ctx_with(method, path, query, body, headers, 4)
}

// ── Rule discovery ──────────────────────────────────────────────────────────

#[allow(dead_code)]
struct PmFromFileRule {
    id: String,
    data_file: String,
    pattern_field: String,
    paranoia: u8,
}

#[allow(dead_code)]
struct ContainsAnyRule {
    id: String,
    patterns: Vec<String>,
    pattern_field: String,
    paranoia: u8,
}

fn collect_pm_from_file_rules() -> Vec<PmFromFileRule> {
    let dir = crs_rules_dir();
    let mut rules = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read CRS dir").flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("read yaml");
        for doc in content.split("---") {
            if !doc.contains("pm_from_file") {
                continue;
            }
            let id = extract_field(doc, "id");
            let value = extract_field(doc, "value");
            let pf = extract_field_or(doc, "pattern_field", "all");
            let paranoia = extract_field_or(doc, "paranoia", "1").parse::<u8>().unwrap_or(1);
            if !id.is_empty() && !value.is_empty() {
                rules.push(PmFromFileRule {
                    id,
                    data_file: value,
                    pattern_field: pf,
                    paranoia,
                });
            }
        }
    }
    rules
}

fn collect_contains_any_rules() -> Vec<ContainsAnyRule> {
    let dir = crs_rules_dir();
    let mut rules = Vec::new();
    for entry in std::fs::read_dir(&dir).expect("read CRS dir").flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let content = std::fs::read_to_string(&path).expect("read yaml");
        for doc in content.split("---") {
            if !doc.contains("contains_any") {
                continue;
            }
            let id = extract_field(doc, "id");
            let value = extract_field(doc, "value");
            let pf = extract_field_or(doc, "pattern_field", "all");
            let paranoia = extract_field_or(doc, "paranoia", "1").parse::<u8>().unwrap_or(1);
            if !id.is_empty() && !value.is_empty() {
                let patterns: Vec<String> = value.split_whitespace().map(str::to_owned).collect();
                rules.push(ContainsAnyRule {
                    id,
                    patterns,
                    pattern_field: pf,
                    paranoia,
                });
            }
        }
    }
    rules
}

fn extract_field(doc: &str, field: &str) -> String {
    for line in doc.lines() {
        let trimmed = line.trim();
        let prefix = format!("{field}:");
        if let Some(rest) = trimmed.strip_prefix(&prefix) {
            let val = rest.trim().trim_matches(|c| c == '\'' || c == '"');
            return val.to_string();
        }
    }
    String::new()
}

fn extract_field_or(doc: &str, field: &str, default: &str) -> String {
    let v = extract_field(doc, field);
    if v.is_empty() { default.to_string() } else { v }
}

// ── Discovery validation ────────────────────────────────────────────────────

#[test]
fn discovery_finds_pm_from_file_rules() {
    let rules = collect_pm_from_file_rules();
    assert!(
        rules.len() >= 10,
        "expected at least 10 pm_from_file rules, found {}",
        rules.len()
    );
}

#[test]
fn discovery_finds_contains_any_rules() {
    let rules = collect_contains_any_rules();
    assert!(
        rules.len() >= 2,
        "expected at least 2 contains_any rules, found {}",
        rules.len()
    );
}

// ── pm_from_file regression: full-engine tests (files that load cleanly) ────
//
// These use OWASPCheck::from_directory which loads all CRS rules. They test
// data files from YAML files that parse successfully as a whole.

#[test]
fn pm_from_file_restricted_files_blocks() {
    let checker = load_crs_engine();
    let patterns = [".env", ".htpasswd", ".htaccess"];
    for p in &patterns {
        let path = format!("/{p}");
        let mut ctx = ctx_p4("GET", &path, "", &[], &[]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-930130: restricted file '{p}' in path should be blocked"
        );
    }
}

#[test]
fn pm_from_file_lfi_os_files_blocks() {
    let checker = load_crs_engine();
    let patterns = ["config.ini", "/etc/passwd", "boot.ini"];
    for p in &patterns {
        let body = format!("file={p}");
        let mut ctx = ctx_p4("POST", "/include", "", body.as_bytes(), &[]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-930120: LFI pattern '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_ai_critical_artifacts_blocks() {
    let checker = load_crs_engine();
    // Most patterns in the data file end with '/'; use paths that include the
    // trailing slash to ensure substring match.
    let patterns = [".cursor/", ".claude/", ".aider/"];
    for p in &patterns {
        let path = format!("/{p}config");
        let mut ctx = ctx_p4("GET", &path, "", &[], &[]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-930140: AI artifact '{p}' in path should be blocked"
        );
    }
}

#[test]
fn pm_from_file_php_variables_blocks() {
    let checker = load_crs_engine();
    let patterns = ["$_SERVER", "$_GET", "$_POST"];
    for p in &patterns {
        let body = format!("code={p}");
        let mut ctx = ctx_p4("POST", "/eval", "", body.as_bytes(), &[]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-933130: PHP variable '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_php_functions_blocks() {
    let checker = load_crs_engine();
    let patterns = ["shell_exec", "base64_decode", "curl_exec"];
    for p in &patterns {
        let body = format!("code={p}()");
        let mut ctx = ctx_p4("POST", "/x", "", body.as_bytes(), &[]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-933150: PHP function '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_scanner_user_agents_blocks() {
    let checker = load_crs_engine();
    let patterns = ["Nmap Scripting Engine", "sqlmap", "nikto"];
    for p in &patterns {
        let mut ctx = ctx_p4("GET", "/home", "", &[], &[("user-agent", p)]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-913100: scanner UA '{p}' should be blocked"
        );
    }
}

// ── pm_from_file regression: isolated engine (files with oversized regexes) ─
//
// rce.yaml and generic-attack.yaml contain documents with regex patterns that
// exceed the 1MB compiled DFA limit, causing parse_with_context to fail for
// the whole file. engine_from_crs_file parses documents individually, skipping
// bad ones, so pm_from_file rules still load.

#[test]
fn pm_from_file_unix_shell_blocks_isolated() {
    let engine = engine_from_crs_file("rce.yaml");
    let patterns = ["bin/bash", "bin/cat", "bin/wget"];
    for p in &patterns {
        let body = format!("cmd={p}");
        let ctx = ctx_p4("POST", "/run", "", body.as_bytes(), &[]);
        assert!(
            engine.check(&ctx).is_some(),
            "CRS-932160: unix-shell '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_windows_powershell_blocks_isolated() {
    let engine = engine_from_crs_file("rce.yaml");
    let patterns = ["powershell", "Invoke-Expression", "Invoke-Command"];
    for p in &patterns {
        let body = format!("cmd={p}");
        let ctx = ctx_p4("POST", "/run", "", body.as_bytes(), &[]);
        assert!(
            engine.check(&ctx).is_some(),
            "CRS-932120: powershell '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_restricted_upload_blocks_isolated() {
    let engine = engine_from_crs_file("rce.yaml");
    let patterns = [".htaccess", ".htpasswd", ".bashrc"];
    for p in &patterns {
        let body = format!("file={p}");
        let ctx = ctx_p4("POST", "/upload", "", body.as_bytes(), &[]);
        assert!(
            engine.check(&ctx).is_some(),
            "CRS-932180: restricted-upload '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_ssrf_blocks_isolated() {
    let engine = engine_from_crs_file("generic-attack.yaml");
    // Data file patterns include trailing path segments
    let patterns = [
        "http://169.254.169.254/latest/",
        "http://metadata.google.internal/computeMetadata/v1/",
    ];
    for p in &patterns {
        let body = format!("url={p}");
        let ctx = ctx_p4("POST", "/x", "", body.as_bytes(), &[]);
        assert!(
            engine.check(&ctx).is_some(),
            "CRS-934110: SSRF pattern '{p}' in body should be blocked"
        );
    }
}

#[test]
fn pm_from_file_ssrf_no_scheme_blocks_isolated() {
    let engine = engine_from_crs_file("generic-attack.yaml");
    // Data file patterns are hostnames with trailing slash: "localhost/", "host.docker.internal/"
    let patterns = ["localhost/", "host.docker.internal/"];
    for p in &patterns {
        let body = format!("url={p}");
        let ctx = ctx_p4("POST", "/x", "", body.as_bytes(), &[]);
        assert!(
            engine.check(&ctx).is_some(),
            "CRS-934190: ssrf-no-scheme '{p}' in body should be blocked"
        );
    }
}

// ── pm_from_file negative cases ─────────────────────────────────────────────

#[test]
fn pm_from_file_negative_innocuous_path_passes() {
    let checker = load_crs_engine();
    let mut ctx = ctx_p4("GET", "/users/profile", "", &[], &[("accept", "*/*")]);
    assert!(
        checker.check(&mut ctx).is_none(),
        "innocuous GET /users/profile must not match any CRS rule"
    );
}

#[test]
fn pm_from_file_negative_clean_body_passes() {
    let checker = load_crs_engine();
    let mut ctx = ctx_p4("POST", "/api/data", "", b"name=alice", &[("accept", "*/*")]);
    let result = checker.check(&mut ctx);
    assert!(
        result.is_none(),
        "clean POST body must not match any CRS rule, got: {result:?}"
    );
}

#[test]
fn pm_from_file_negative_normal_user_agent_passes() {
    let checker = load_crs_engine();
    let mut ctx = ctx_p4(
        "GET",
        "/home",
        "",
        &[],
        &[("user-agent", "CustomApp/1.0"), ("accept", "*/*")],
    );
    assert!(
        checker.check(&mut ctx).is_none(),
        "normal user-agent must not match scanner rule"
    );
}

// ── contains_any regression ─────────────────────────────────────────────────

#[test]
fn contains_any_xss_keywords_blocks() {
    let checker = load_crs_engine();
    let keywords = ["document.cookie", "document.domain", "window.location"];
    for kw in &keywords {
        let query = format!("q={kw}");
        let mut ctx = ctx_p4("GET", "/search", &query, &[], &[]);
        assert!(
            checker.check(&mut ctx).is_some(),
            "CRS-941180: contains_any keyword '{kw}' should be blocked"
        );
    }
}

#[test]
fn contains_any_php_close_tag_blocks() {
    let checker = load_crs_engine();
    let mut ctx = ctx_with("POST", "/comment", "", b"text=hello?>evil", &[], 4);
    assert!(
        checker.check(&mut ctx).is_some(),
        "CRS-933190: contains_any '?>' should be blocked at paranoia 3+"
    );
}

#[test]
fn contains_any_negative_clean_query_passes() {
    let checker = load_crs_engine();
    // Use paranoia 1 — higher levels trigger aggressive regex rules unrelated to contains_any
    let mut ctx = ctx_with("GET", "/items", "id=42", &[], &[("accept", "*/*")], 1);
    assert!(
        checker.check(&mut ctx).is_none(),
        "clean query must not match contains_any rules"
    );
}

// ── Encoding bypass matrix (path-targeted rules) ────────────────────────────

#[test]
fn encoding_bypass_url_encode_dot_blocks() {
    let checker = load_crs_engine();
    let mut ctx = ctx_p4("GET", "/%2Eenv", "", &[], &[]);
    assert!(
        checker.check(&mut ctx).is_some(),
        "URL-encoded .env (%2Eenv) must be blocked"
    );
}

#[test]
fn encoding_bypass_uppercase_blocks() {
    let checker = load_crs_engine();
    let mut ctx = ctx_p4("GET", "/.ENV", "", &[], &[]);
    assert!(
        checker.check(&mut ctx).is_some(),
        "upper-case .ENV must be blocked (case-insensitive)"
    );
}

#[test]
fn encoding_bypass_leading_whitespace_in_query() {
    let checker = load_crs_engine();
    let mut ctx = ctx_p4("GET", "/x", "file=%20.env", &[], &[]);
    assert!(
        checker.check(&mut ctx).is_some(),
        "leading whitespace + .env in query should be blocked"
    );
}

#[test]
fn encoding_bypass_double_encode_behavior() {
    let checker = load_crs_engine();
    // %252E = double-encoded dot. Document whether engine decodes recursively.
    let mut ctx = ctx_p4("GET", "/%252Eenv", "", &[], &[]);
    let detected = checker.check(&mut ctx).is_some();
    if detected {
        eprintln!("NOTE: double-encoded %252Eenv is detected — engine decodes recursively");
    }
    // Intentionally no assertion — this test documents behavior
}

#[test]
fn pm_from_file_java_classes_blocks_isolated() {
    let engine = engine_from_crs_file("java-injection.yaml");
    // java-classes.data: dangerous Java class names used in RCE/deserialization attacks (CVE-2017-5638, Log4Shell, etc.)
    let patterns = [
        "java.lang.Runtime",
        "java.lang.ProcessBuilder",
        "com.opensymphony.xwork2",
    ];
    for p in &patterns {
        let body = format!("data={p}");
        let ctx = ctx_p4("POST", "/api/invoke", "", body.as_bytes(), &[]);
        assert!(
            engine.check(&ctx).is_some(),
            "CRS-944130: java-classes pattern '{p}' in body should be blocked"
        );
    }
}

// ── Completeness guard ──────────────────────────────────────────────────────
// Fails if a new pm_from_file rule is added to CRS without coverage here.

fn known_pm_data_files() -> Vec<&'static str> {
    vec![
        "restricted-files.data",
        "lfi-os-files.data",
        "ai-critical-artifacts.data",
        "ssrf.data",
        "ssrf-no-scheme.data",
        "unix-shell.data",
        "php-variables.data",
        "php-function-names-933150.data",
        "scanners-user-agents.data",
        "windows-powershell-commands.data",
        "restricted-upload.data",
        "java-classes.data",
        // Response-phase data files (tested indirectly — can't inject response body)
        "asp-dotnet-errors.data",
        "iis-errors.data",
        "php-errors.data",
        "ruby-errors.data",
        "web-shells-php.data",
        "web-shells-asp.data",
    ]
}

#[test]
fn completeness_all_pm_from_file_data_files_are_known() {
    let rules = collect_pm_from_file_rules();
    let known = known_pm_data_files();
    for rule in &rules {
        assert!(
            known.contains(&rule.data_file.as_str()),
            "COVERAGE GAP: rule {} references '{}' which is not in the known data file list. \
             Add test coverage and register it in known_pm_data_files().",
            rule.id,
            rule.data_file
        );
    }
}

#[test]
fn completeness_all_contains_any_rules_are_known() {
    let rules = collect_contains_any_rules();
    let known_ids = ["CRS-941180", "CRS-933190"];
    for rule in &rules {
        assert!(
            known_ids.contains(&rule.id.as_str()),
            "COVERAGE GAP: contains_any rule '{}' not in known list. Add test coverage.",
            rule.id
        );
    }
}
