//! YAML parser for FR-003 file-based `CustomRule` definitions.
//!
//! Each YAML document is gated by the discriminator `kind: custom_rule_v1`.
//! Documents without a `kind` field are silently skipped — this allows the
//! same directory to hold registry-format YAML and custom-rule YAML side by
//! side. Documents whose `kind` starts with `custom_rule_` but is not `v1`
//! are rejected as a forward-compatibility safeguard.

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use super::super::engine::{Condition, ConditionNode, ConditionOp, CustomRule, RuleAction};

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
}

fn default_host() -> String {
    "*".to_string()
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
        out.push(to_custom_rule(dto));
    }
    Ok(out)
}

fn to_custom_rule(dto: YamlCustomRule) -> CustomRule {
    CustomRule {
        id: dto.id,
        host_code: dto.host_code,
        name: dto.name,
        priority: dto.priority,
        enabled: dto.enabled,
        condition_op: dto.condition_op,
        conditions: dto.conditions,
        action: dto.action,
        action_status: dto.action_status,
        action_msg: dto.action_msg,
        script: dto.script,
        match_tree: dto.match_tree,
    }
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
}
