//! YAML parser for FR-003 file-based `CustomRule` definitions.
//!
//! Each YAML document is gated by the discriminator `kind: custom_rule_v1`.
//! Documents without a `kind` field are silently skipped — this allows the
//! same directory to hold registry-format YAML and custom-rule YAML side by
//! side. Documents whose `kind` starts with `custom_rule_` but is not `v1`
//! are rejected as a forward-compatibility safeguard.

use std::collections::HashMap;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use super::super::engine::{
    Condition, ConditionField, ConditionNode, ConditionOp, ConditionValue, CustomRule, Operator, RuleAction,
};

/// Wire DTO — mirrors `CustomRule` plus the `kind` discriminator.
///
/// Fields with `serde(default)` accept omission; `default = "..."` supplies
/// a non-`Default` constant.
#[derive(Debug, Deserialize)]
struct YamlCustomRule {
    id: String,
    #[serde(default = "default_host")]
    host_code: String,
    name: String,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    condition_op: ConditionOp,
    #[serde(default)]
    conditions: Vec<Condition>,
    #[serde(default)]
    match_tree: Option<ConditionNode>,
    #[serde(default = "default_action")]
    action: RuleAction,
    #[serde(default = "default_status")]
    action_status: u16,
    #[serde(default)]
    action_msg: Option<String>,
    #[serde(default)]
    script: Option<String>,
    /// FR-025: Risk score delta when this rule matches.
    #[serde(default)]
    risk_delta: Option<i16>,
    /// FR-025: Override action for risk scoring.
    #[serde(default)]
    risk_action: Option<String>,
    // ── Registry/OWASP compatibility fields ──
    /// Regex pattern string evaluated against `pattern_field`.
    #[serde(default)]
    pattern: Option<String>,
    /// Which request field to check: "all", "path", "query", "body", "method", "headers", "cookies".
    #[serde(default = "default_field")]
    pattern_field: String,
    /// Operator shorthand for Registry format — auto-converted to Condition.
    #[serde(default)]
    operator: Option<String>,
    /// Value for operator shorthand — auto-converted to `ConditionValue`.
    #[serde(default)]
    value: Option<serde_yaml::Value>,
    /// Rule category: sqli, xss, rce, ssti, ssrf, etc.
    #[serde(default)]
    category: Option<String>,
    /// Severity: critical, high, medium, low.
    #[serde(default)]
    severity: Option<String>,
    /// OWASP CRS paranoia level (1-4).
    #[serde(default)]
    paranoia: Option<u8>,
    /// Tags for rule filtering and grouping.
    #[serde(default)]
    tags: Vec<String>,
    /// Arbitrary key-value metadata.
    #[serde(default)]
    metadata: HashMap<String, String>,
    /// External reference URL (CVE, documentation).
    #[serde(default)]
    reference: Option<String>,
}

fn default_host() -> String {
    "*".to_string()
}
fn default_field() -> String {
    "all".to_string()
}
const fn default_true() -> bool {
    true
}
const fn default_action() -> RuleAction {
    RuleAction::Block
}
const fn default_status() -> u16 {
    403
}

const KIND_V1: &str = "custom_rule_v1";
const KIND_PREFIX: &str = "custom_rule_";

/// Parse a YAML stream into a list of `CustomRule`s.
///
/// Multi-document YAML is supported (`---` separators). Documents without
/// a `kind: custom_rule_v1` discriminator are skipped silently; documents
/// that look like a versioned variant we don't recognise return `Err`.
pub fn parse(content: &str) -> Result<Vec<CustomRule>> {
    let mut out = Vec::new();
    for (idx, doc) in serde_yaml::Deserializer::from_str(content).enumerate() {
        let value =
            serde_yaml::Value::deserialize(doc).with_context(|| format!("invalid YAML in document #{}", idx + 1))?;

        // Only mappings can carry a discriminator; everything else (lists,
        // scalars, null) is treated as unrelated content and skipped.
        let Some(map) = value.as_mapping() else {
            continue;
        };

        let kind_val = map.get(serde_yaml::Value::String("kind".into()));
        let Some(kind) = kind_val.and_then(serde_yaml::Value::as_str) else {
            continue; // no discriminator → not ours
        };

        if kind != KIND_V1 {
            if kind.starts_with(KIND_PREFIX) {
                bail!(
                    "document #{}: unsupported kind '{}', expected '{}'",
                    idx + 1,
                    kind,
                    KIND_V1
                );
            }
            continue; // some other discriminator entirely
        }

        let dto: YamlCustomRule = serde_yaml::from_value(value.clone())
            .with_context(|| format!("document #{}: failed to parse custom_rule_v1", idx + 1))?;
        let rule =
            to_custom_rule(dto).with_context(|| format!("document #{}: failed to convert custom_rule_v1", idx + 1))?;
        out.push(rule);
    }
    Ok(out)
}

fn to_custom_rule(dto: YamlCustomRule) -> Result<CustomRule> {
    let pattern = match &dto.pattern {
        Some(p) => Some(
            regex::RegexBuilder::new(p)
                .size_limit(1 << 20) // 1 MB compiled DFA limit — guards against regex DoS
                .build()
                .with_context(|| format!("invalid pattern regex: {p}"))?,
        ),
        None => None,
    };

    // Auto-convert Registry-style operator+value shorthand to a condition
    // when no conditions, match_tree, or pattern are present.
    // Specialised operators (pm_from_file, detect_sqli, detect_xss,
    // contains_any) are stored in `specialised_op` for dispatch by the engine.
    let mut conditions = dto.conditions;
    let mut specialised_op = None;
    if conditions.is_empty()
        && dto.match_tree.is_none()
        && pattern.is_none()
        && let (Some(op_str), Some(val)) = (&dto.operator, &dto.value)
    {
        let operator = parse_operator_str(op_str)?;
        if is_specialised_operator(&operator) {
            specialised_op = Some(operator);
        } else {
            let field = parse_pattern_field_to_condition(&dto.pattern_field);
            let value = yaml_value_to_condition_value(val)?;
            conditions.push(Condition { field, operator, value });
        }
    }

    Ok(CustomRule {
        id: dto.id,
        host_code: dto.host_code,
        name: dto.name,
        priority: dto.priority,
        enabled: dto.enabled,
        condition_op: dto.condition_op,
        conditions,
        action: dto.action,
        action_status: dto.action_status,
        action_msg: dto.action_msg,
        script: dto.script,
        match_tree: dto.match_tree,
        risk_delta: dto.risk_delta,
        risk_action: dto.risk_action,
        pattern,
        pattern_field: dto.pattern_field,
        category: dto.category,
        severity: dto.severity,
        paranoia: dto.paranoia,
        tags: dto.tags,
        metadata: dto.metadata,
        reference: dto.reference,
        specialised_op,
    })
}

/// Map a `pattern_field` string to a `ConditionField` for auto-conversion.
/// Falls back to `Body` for unknown fields (most Registry rules target body).
fn parse_pattern_field_to_condition(field: &str) -> ConditionField {
    match field {
        "path" => ConditionField::Path,
        "query" => ConditionField::Query,
        "method" => ConditionField::Method,
        "cookies" | "cookie" => ConditionField::Cookie(None),
        "host" => ConditionField::Host,
        "user_agent" => ConditionField::UserAgent,
        "content_type" => ConditionField::ContentType,
        "content_length" => ConditionField::ContentLength,
        "ip" => ConditionField::Ip,
        "response_body" => ConditionField::ResponseBody,
        "all" | "body" | "headers" => ConditionField::Body,
        other => {
            tracing::warn!(field = other, "unknown pattern_field; falling back to Body");
            ConditionField::Body
        }
    }
}

/// Parse an operator string from OWASP/Registry format to `Operator`.
fn parse_operator_str(s: &str) -> Result<Operator> {
    Ok(match s {
        "eq" | "equals" => Operator::Eq,
        "ne" => Operator::Ne,
        "contains" => Operator::Contains,
        "not_contains" => Operator::NotContains,
        "starts_with" => Operator::StartsWith,
        "ends_with" => Operator::EndsWith,
        "regex" => Operator::Regex,
        "wildcard" => Operator::Wildcard,
        "in" | "in_list" => Operator::InList,
        "not_in" | "not_in_list" => Operator::NotInList,
        "cidr_match" => Operator::CidrMatch,
        "gt" => Operator::Gt,
        "lt" => Operator::Lt,
        "gte" => Operator::Gte,
        "lte" => Operator::Lte,
        "pm_from_file" => Operator::PmFromFile,
        "detect_sqli" => Operator::DetectSqli,
        "detect_xss" => Operator::DetectXss,
        "contains_any" => Operator::ContainsAny,
        other => bail!("unknown operator: {other}"),
    })
}

/// Operators evaluated by specialised modules, not the generic condition matcher.
const fn is_specialised_operator(op: &Operator) -> bool {
    matches!(
        op,
        Operator::PmFromFile | Operator::DetectSqli | Operator::DetectXss | Operator::ContainsAny
    )
}

/// Convert a `serde_yaml::Value` to `ConditionValue`.
fn yaml_value_to_condition_value(val: &serde_yaml::Value) -> Result<ConditionValue> {
    if let Some(s) = val.as_str() {
        return Ok(ConditionValue::Str(s.to_owned()));
    }
    if let Some(n) = val.as_i64() {
        return Ok(ConditionValue::Number(n));
    }
    if let Some(seq) = val.as_sequence() {
        let list: Vec<String> = seq
            .iter()
            .map(|v| {
                v.as_str()
                    .map(String::from)
                    .or_else(|| v.as_i64().map(|n| n.to_string()))
                    .ok_or_else(|| anyhow::anyhow!("unsupported list element type"))
            })
            .collect::<Result<Vec<_>>>()?;
        return Ok(ConditionValue::List(list));
    }
    bail!("unsupported condition value type")
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::rules::engine::{ConditionField, ConditionNode, Operator};

    #[test]
    fn parse_minimal_v1_rule() {
        let yaml = r"
kind: custom_rule_v1
id: r-001
name: Block admin
conditions:
  - field: path
    operator: starts_with
    value: /admin
";
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.id, "r-001");
        assert_eq!(r.host_code, "*");
        assert_eq!(r.priority, 0);
        assert!(r.enabled);
        assert_eq!(r.action_status, 403);
        assert!(matches!(r.action, RuleAction::Block));
        assert!(matches!(r.condition_op, ConditionOp::And));
        assert_eq!(r.conditions.len(), 1);
    }

    #[test]
    fn parse_full_v1_rule_match_tree() {
        let yaml = r#"
kind: custom_rule_v1
id: r-002
host_code: api-host
name: Nested tree
priority: 5
enabled: false
action: log
action_status: 401
action_msg: "blocked by tree"
match_tree:
  and:
    - or:
        - field: ip
          operator: cidr_match
          value: 10.0.0.0/8
        - field: {cookie: session}
          operator: eq
          value: bad
    - not:
        field: method
        operator: eq
        value: GET
"#;
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.host_code, "api-host");
        assert_eq!(r.priority, 5);
        assert!(!r.enabled);
        assert!(matches!(r.action, RuleAction::Log));
        assert_eq!(r.action_status, 401);
        assert_eq!(r.action_msg.as_deref(), Some("blocked by tree"));
        let tree = r.match_tree.as_ref().expect("match_tree present");
        match tree {
            ConditionNode::And(b) => assert_eq!(b.and.len(), 2),
            _ => panic!("expected And root"),
        }
    }

    #[test]
    fn parse_skips_doc_without_kind() {
        // Registry-format YAML is a top-level sequence — no `kind` field.
        let yaml = r"
- id: TEST-001
  name: legacy registry rule
";
        let rules = parse(yaml).unwrap();
        assert!(rules.is_empty());
    }

    #[test]
    fn parse_rejects_unknown_kind() {
        let yaml = r"
kind: custom_rule_v999
id: r-x
name: future
";
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("custom_rule_v999"), "msg={msg}");
    }

    #[test]
    fn parse_multi_doc_stream() {
        let yaml = r"
kind: custom_rule_v1
id: a
name: rule a
conditions:
  - field: path
    operator: eq
    value: /a
---
# this doc has no `kind` and should be skipped
foo: bar
---
kind: custom_rule_v1
id: b
name: rule b
conditions:
  - field: path
    operator: eq
    value: /b
";
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].id, "a");
        assert_eq!(rules[1].id, "b");
    }

    #[test]
    fn parse_missing_id_errors() {
        let yaml = r"
kind: custom_rule_v1
name: no id here
";
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("custom_rule_v1"), "msg={msg}");
    }

    #[test]
    fn parse_cookie_newtype_field() {
        let yaml = r"
kind: custom_rule_v1
id: ck
name: cookie test
conditions:
  - field: {cookie: session}
    operator: eq
    value: abc
";
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        let cond = &rules[0].conditions[0];
        match &cond.field {
            ConditionField::Cookie(Some(name)) => assert_eq!(name, "session"),
            other => panic!("expected Cookie(Some), got {other:?}"),
        }
        assert!(matches!(cond.operator, Operator::Eq));
    }

    #[test]
    fn parse_invalid_match_tree_errors() {
        // `not` branch without inner content → typed deserialise fails.
        let yaml = r"
kind: custom_rule_v1
id: bad-tree
name: malformed
match_tree:
  and:
    - not: 42
";
        let err = parse(yaml).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("custom_rule_v1") || msg.contains("not"), "msg={msg}");
    }

    #[test]
    fn parse_response_body_field_maps_correctly() {
        let yaml = r"
kind: custom_rule_v1
id: rb-yaml-001
name: Detect web shell in response
pattern: 'r57shell|c99shell'
pattern_field: response_body
category: web-shell
severity: critical
paranoia: 1
";
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pattern_field, "response_body");
        assert!(rules[0].pattern.is_some());
    }

    #[test]
    fn parse_response_body_operator_shorthand() {
        let yaml = r"
kind: custom_rule_v1
id: rb-yaml-002
name: Response body contains error
pattern_field: response_body
operator: contains
value: 'SQL syntax error'
";
        let rules = parse(yaml).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].conditions.len(), 1);
        assert!(matches!(rules[0].conditions[0].field, ConditionField::ResponseBody));
    }

    #[test]
    fn parse_geoip_country_blocklist_yaml() {
        let yaml = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/geoip/country-blocklist.yaml"),
        )
        .unwrap();
        let rules = parse(&yaml).unwrap();
        assert_eq!(rules.len(), 2, "expected 2 GeoIP rules");

        assert_eq!(rules[0].id, "GEO-COUNTRY-001");
        assert_eq!(rules[0].conditions.len(), 1);
        assert!(matches!(rules[0].conditions[0].field, ConditionField::GeoIso));
        assert!(matches!(rules[0].conditions[0].operator, Operator::InList));
        assert!(matches!(rules[0].action, RuleAction::Block));

        assert_eq!(rules[1].id, "GEO-COUNTRY-002");
        assert!(matches!(rules[1].conditions[0].field, ConditionField::GeoIsp));
        assert!(matches!(rules[1].conditions[0].operator, Operator::Contains));
        assert!(matches!(rules[1].action, RuleAction::Log));
    }

    #[test]
    fn parse_dos_protection_yaml() {
        let yaml = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/modsecurity/dos-protection.yaml"),
        )
        .unwrap();
        let rules = parse(&yaml).unwrap();
        assert_eq!(rules.len(), 12, "expected 12 DoS rules");

        // DOS-001: content_length gt (conditions)
        assert_eq!(rules[0].id, "MODSEC-DOS-001");
        assert_eq!(rules[0].conditions.len(), 1);
        assert!(matches!(rules[0].conditions[0].field, ConditionField::ContentLength));
        assert!(matches!(rules[0].conditions[0].operator, Operator::Gt));

        // DOS-002: script-based (path.len() > 1024)
        assert_eq!(rules[1].id, "MODSEC-DOS-002");
        assert!(rules[1].script.is_some());

        // DOS-003: script-based (query arg count)
        assert_eq!(rules[2].id, "MODSEC-DOS-003");
        assert!(rules[2].script.is_some());

        // DOS-004: headers regex pattern
        assert_eq!(rules[3].id, "MODSEC-DOS-004");
        assert!(rules[3].pattern.is_some());
        assert_eq!(rules[3].pattern_field, "headers");

        // DOS-005: method regex pattern
        assert_eq!(rules[4].id, "MODSEC-DOS-005");
        assert!(rules[4].pattern.is_some());
        assert_eq!(rules[4].pattern_field, "method");

        // DOS-008: content_length gt (conditions)
        assert_eq!(rules[7].id, "MODSEC-DOS-008");
        assert!(matches!(rules[7].conditions[0].operator, Operator::Gt));

        // DOS-009: body regex pattern
        assert_eq!(rules[8].id, "MODSEC-DOS-009");
        assert!(rules[8].pattern.is_some());
        assert_eq!(rules[8].pattern_field, "body");

        // DOS-010: all field regex pattern (default)
        assert_eq!(rules[9].id, "MODSEC-DOS-010");
        assert!(rules[9].pattern.is_some());
        assert_eq!(rules[9].pattern_field, "all");

        // DOS-011: cookie length via script
        assert_eq!(rules[10].id, "MODSEC-DOS-011");
        assert!(rules[10].script.is_some());

        // DOS-012: content_type regex (conditions)
        assert_eq!(rules[11].id, "MODSEC-DOS-012");
        assert!(matches!(rules[11].conditions[0].field, ConditionField::ContentType));
        assert!(matches!(rules[11].conditions[0].operator, Operator::Regex));
    }
}
