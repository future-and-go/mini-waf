//! Rule format parsers — YAML, `ModSecurity` (`SecRule`), JSON.

pub mod custom_rule_yaml;
pub mod json;
pub mod modsec;
pub mod yaml;

use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::registry::Rule;

/// Supported rule file formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RuleFormat {
    #[default]
    Yaml,
    ModSec,
    Json,
}

impl RuleFormat {
    /// Infer format from file extension.
    pub fn from_path(path: &Path) -> Option<Self> {
        match path.extension()?.to_str()? {
            "yaml" | "yml" => Some(Self::Yaml),
            "conf" | "modsec" => Some(Self::ModSec),
            "json" => Some(Self::Json),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Yaml => "yaml",
            Self::ModSec => "modsec",
            Self::Json => "json",
        }
    }
}

impl std::fmt::Display for RuleFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse rule content from a string given a known format.
///
/// **Note:** `Yaml` and `Json` variants use the legacy Registry parsers.
/// Those parsers log a deprecation warning internally.
/// Prefer `custom_rule_yaml::parse` for new code.
pub fn parse_rules(content: &str, format: RuleFormat) -> Result<Vec<Rule>> {
    match format {
        RuleFormat::Yaml => yaml::parse(content),
        RuleFormat::ModSec => modsec::parse(content),
        RuleFormat::Json => json::parse(content),
    }
}

/// A validation error found while parsing a rule file.
#[derive(Debug, Clone)]
pub struct ValidationError {
    pub line: Option<usize>,
    pub field: Option<String>,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(line) = self.line {
            write!(f, "line {line}: ")?;
        }
        write!(f, "{}", self.message)
    }
}

/// Validate a rule file and return a list of errors (empty = valid).
pub fn validate_rules(content: &str, format: RuleFormat) -> Vec<ValidationError> {
    match parse_rules(content, format) {
        Ok(rules) => {
            let mut errors = Vec::new();
            for (i, rule) in rules.iter().enumerate() {
                if rule.id.is_empty() {
                    errors.push(ValidationError {
                        line: None,
                        field: Some(format!("rules[{i}].id")),
                        message: "Rule id must not be empty".to_string(),
                    });
                }
                if rule.name.is_empty() {
                    errors.push(ValidationError {
                        line: None,
                        field: Some(format!("rules[{i}].name")),
                        message: "Rule name must not be empty".to_string(),
                    });
                }
            }
            errors
        }
        Err(e) => vec![ValidationError {
            line: None,
            field: None,
            message: format!("Parse error: {e}"),
        }],
    }
}

/// Export format for the `rules export` command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Yaml,
    Json,
}

impl ExportFormat {
    pub fn parse_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Yaml,
        }
    }
}

/// Serialize a list of rules to a string in the given format.
pub fn export_rules(rules: &[Rule], format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Yaml => {
            let out = serde_yaml::to_string(rules)?;
            Ok(out)
        }
        ExportFormat::Json => {
            let out = serde_json::to_string_pretty(rules)?;
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    fn sample_rule(id: &str, name: &str) -> Rule {
        Rule {
            id: id.to_string(),
            name: name.to_string(),
            description: None,
            category: "sqli".to_string(),
            source: "test".to_string(),
            enabled: true,
            action: "block".to_string(),
            severity: Some("low".to_string()),
            pattern: None,
            tags: vec![],
            metadata: HashMap::new(),
            risk_delta: None,
            risk_action: None,
        }
    }

    #[test]
    fn rule_format_from_path_known_extensions() {
        assert_eq!(RuleFormat::from_path(&PathBuf::from("a.yaml")), Some(RuleFormat::Yaml));
        assert_eq!(RuleFormat::from_path(&PathBuf::from("a.yml")), Some(RuleFormat::Yaml));
        assert_eq!(
            RuleFormat::from_path(&PathBuf::from("a.conf")),
            Some(RuleFormat::ModSec)
        );
        assert_eq!(
            RuleFormat::from_path(&PathBuf::from("a.modsec")),
            Some(RuleFormat::ModSec)
        );
        assert_eq!(RuleFormat::from_path(&PathBuf::from("a.json")), Some(RuleFormat::Json));
        assert_eq!(RuleFormat::from_path(&PathBuf::from("a.txt")), None);
        assert_eq!(RuleFormat::from_path(&PathBuf::from("noext")), None);
    }

    #[test]
    fn rule_format_as_str_and_display() {
        assert_eq!(RuleFormat::Yaml.as_str(), "yaml");
        assert_eq!(RuleFormat::Json.as_str(), "json");
        assert_eq!(RuleFormat::ModSec.as_str(), "modsec");
        assert_eq!(format!("{}", RuleFormat::Yaml), "yaml");
        assert_eq!(RuleFormat::default(), RuleFormat::Yaml);
    }

    #[test]
    fn export_format_parse_str() {
        assert_eq!(ExportFormat::parse_str("json"), ExportFormat::Json);
        assert_eq!(ExportFormat::parse_str("JSON"), ExportFormat::Json);
        assert_eq!(ExportFormat::parse_str("yaml"), ExportFormat::Yaml);
        // Unknown values fall through to Yaml.
        assert_eq!(ExportFormat::parse_str("toml"), ExportFormat::Yaml);
    }

    #[test]
    fn export_rules_round_trips_for_both_formats() {
        let rules = vec![sample_rule("r1", "first"), sample_rule("r2", "second")];

        let yaml = export_rules(&rules, ExportFormat::Yaml).expect("yaml export");
        assert!(yaml.contains("r1"));
        assert!(yaml.contains("second"));

        let json = export_rules(&rules, ExportFormat::Json).expect("json export");
        assert!(json.contains("\"r1\""));
        assert!(json.contains("\"second\""));
    }

    #[test]
    fn validate_rules_flags_empty_id_and_name() {
        // Use JSON so we can craft known-bad rules without depending on yaml grammar.
        let json_payload = r#"[
            {"id":"","name":"missing-id","category":"c","source":"s","enabled":true,"action":"block"},
            {"id":"x","name":"","category":"c","source":"s","enabled":true,"action":"block"}
        ]"#;
        let errors = validate_rules(json_payload, RuleFormat::Json);
        assert_eq!(errors.len(), 2);
        let messages: Vec<_> = errors.iter().map(|e| e.message.clone()).collect();
        assert!(messages.iter().any(|m| m.contains("id")));
        assert!(messages.iter().any(|m| m.contains("name")));
    }

    #[test]
    fn validate_rules_returns_parse_error_on_garbage_input() {
        let errors = validate_rules("{not valid json", RuleFormat::Json);
        assert_eq!(errors.len(), 1);
        let first = errors.first().expect("at least one error");
        assert!(first.message.starts_with("Parse error"));
    }

    #[test]
    fn validation_error_display_includes_line_when_present() {
        let with_line = ValidationError {
            line: Some(7),
            field: None,
            message: "boom".to_string(),
        };
        assert_eq!(format!("{with_line}"), "line 7: boom");

        let without_line = ValidationError {
            line: None,
            field: None,
            message: "boom".to_string(),
        };
        assert_eq!(format!("{without_line}"), "boom");
    }
}
