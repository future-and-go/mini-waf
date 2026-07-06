//! `ModSecurity` `SecRule` parser — basic subset.
//!
//! Supported directives: `SecRule`
//! Supported variables: `ARGS`, `REQUEST_HEADERS`, `REQUEST_URI`, `REQUEST_BODY`, `REQUEST_METHOD`
//! Supported operators: `@rx` (regex), `@contains`, `@beginsWith`, `@endsWith`, `@ipMatch`
//! Supported actions: deny, pass, log, block, redirect, allow
//! Continuation lines via `\` are supported.

use std::collections::HashMap;

use anyhow::{Result, bail};

use super::super::registry::Rule;

/// Parse a `ModSecurity` rule file into the internal `Rule` format.
pub fn parse(content: &str) -> Result<Vec<Rule>> {
    // Join continuation lines
    let joined = join_lines(content);
    let mut rules = Vec::new();

    for (line_no, line) in joined.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.to_uppercase().starts_with("SECRULE ") {
            match parse_secrule(line, line_no + 1) {
                Ok(rule) => rules.push(rule),
                Err(e) => {
                    tracing::warn!("modsec parse error at line {}: {e}", line_no + 1);
                }
            }
        }
        // Ignore other directives (SecDefaultAction, SecComponentSignature, etc.)
    }

    Ok(rules)
}

/// Join continuation lines (lines ending with `\`).
fn join_lines(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut pending: Option<String> = None;

    for line in content.lines() {
        if let Some(stripped) = line.strip_suffix('\\') {
            let base = pending.take().unwrap_or_default();
            pending = Some(format!("{}{} ", base, stripped.trim_end()));
        } else {
            if let Some(base) = pending.take() {
                out.push_str(&base);
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    if let Some(base) = pending {
        out.push_str(&base);
        out.push('\n');
    }
    out
}

/// Parse a single `SecRule VARIABLES OPERATOR "ACTIONS"` line.
fn parse_secrule(line: &str, line_no: usize) -> Result<Rule> {
    // Strip "SecRule " prefix (case-insensitive)
    let rest = &line["SecRule ".len()..];

    // Split into: VARIABLES  OPERATOR  "ACTIONS"
    // Variables: everything up to first whitespace
    // Operator: next token (could be @rx, @contains, etc.) wrapped in quotes or bare
    // Actions: last quoted string

    let parts = split_secrule_parts(rest);
    if parts.len() < 3 {
        bail!("line {line_no}: expected VARIABLES OPERATOR ACTIONS, got {line}");
    }

    // SAFETY: length checked >= 3 above
    let Some(variables) = parts.first() else {
        bail!("line {line_no}: missing VARIABLES");
    };
    let Some(operator_str) = parts.get(1) else {
        bail!("line {line_no}: missing OPERATOR");
    };
    let Some(actions_str) = parts.get(2) else {
        bail!("line {line_no}: missing ACTIONS");
    };

    // Parse operator and value
    let (op_name, op_value) = parse_operator(operator_str);

    // Parse actions into a map
    let actions = parse_actions(actions_str);

    let id = actions
        .get("id")
        .map_or_else(|| format!("MODSEC-LINE-{line_no}"), |s| format!("MODSEC-{s}"));

    let name = actions
        .get("msg")
        .cloned()
        .unwrap_or_else(|| format!("ModSecurity rule {id}"));

    let action = if actions.contains_key("deny") || actions.contains_key("block") {
        "block"
    } else if actions.contains_key("allow") || actions.contains_key("pass") {
        "allow"
    } else {
        "log"
    }
    .to_string();

    let category = infer_category(variables, &op_value);

    let mut metadata = HashMap::new();
    metadata.insert("variables".to_string(), variables.clone());
    metadata.insert("operator".to_string(), op_name.to_string());
    if let Some(phase) = actions.get("phase") {
        metadata.insert("phase".to_string(), phase.clone());
    }
    if let Some(status) = actions.get("status") {
        metadata.insert("status".to_string(), status.clone());
    }

    Ok(Rule {
        id,
        name,
        description: actions.get("msg").cloned(),
        category,
        source: "modsec".to_string(),
        enabled: true,
        action,
        severity: actions.get("severity").cloned(),
        pattern: Some(op_value),
        tags: vec!["modsec".to_string()],
        metadata,
        risk_delta: None,
        risk_action: None,
    })
}

/// Split `VARIABLES OPERATOR ACTIONS_STRING` respecting quotes.
fn split_secrule_parts(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                if !in_quotes && !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            ' ' | '\t' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Parse an operator string like `@rx pattern` or `"@contains foo"`.
fn parse_operator(op: &str) -> (&'static str, String) {
    let op = op.trim_matches('"');
    if let Some(rest) = op.strip_prefix("@rx ") {
        return ("regex", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@contains ") {
        return ("contains", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@beginsWith ") {
        return ("beginsWith", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@endsWith ") {
        return ("endsWith", rest.to_string());
    }
    if let Some(rest) = op.strip_prefix("@ipMatch ") {
        return ("ipMatch", rest.to_string());
    }
    // bare regex without @rx
    ("regex", op.to_string())
}

/// Parse comma-separated actions like `id:1001,phase:1,deny,status:403,msg:'XSS'`.
fn parse_actions(actions: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for part in actions.split(',') {
        let part = part.trim().trim_matches('"').trim_matches('\'');
        if let Some((k, v)) = part.split_once(':') {
            map.insert(k.trim().to_lowercase(), v.trim().trim_matches('\'').to_string());
        } else if !part.is_empty() {
            map.insert(part.to_lowercase(), String::new());
        }
    }
    map
}

/// Infer a rule category from variable names and operator value.
fn infer_category(variables: &str, value: &str) -> String {
    let v = variables.to_lowercase();
    let val = value.to_lowercase();

    if val.contains("union") && val.contains("select") {
        return "sqli".to_string();
    }
    if val.contains("<script") || val.contains("javascript:") {
        return "xss".to_string();
    }
    if val.contains("../") || val.contains("..\\") {
        return "traversal".to_string();
    }
    if v.contains("request_uri") {
        return "path".to_string();
    }
    if v.contains("args") {
        return "input".to_string();
    }
    "custom".to_string()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_secrule() {
        let content = r#"SecRule REQUEST_URI "@rx /admin" "id:1001,phase:1,deny,status:403,msg:'Admin blocked'"
"#;
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].id, "MODSEC-1001");
        assert_eq!(rules[0].action, "block");
    }

    #[test]
    fn parse_continuation_line() {
        let content = "SecRule ARGS \"@contains <script>\" \\\n    \"id:1002,phase:2,deny,msg:'XSS'\"\n";
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn skip_comments() {
        let content = "# This is a comment\nSecRule REQUEST_URI \"@rx /test\" \"id:1003,deny\"\n";
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn malformed_secrule_is_skipped_not_fatal() {
        let content = "SecRule ONLY_VARIABLES\nSecRule REQUEST_URI \"@rx /ok\" \"id:1,deny\"\n";
        let rules = parse(content).unwrap();
        assert_eq!(rules.len(), 1, "bad line skipped, good line kept");
        assert_eq!(rules[0].id, "MODSEC-1");
    }

    #[test]
    fn lowercase_secrule_directive_is_accepted() {
        let rules = parse("secrule REQUEST_URI \"@rx /x\" \"id:9,deny\"\n").unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn missing_id_falls_back_to_line_number() {
        let rules = parse("SecRule REQUEST_URI \"@rx /x\" \"deny\"\n").unwrap();
        assert_eq!(rules[0].id, "MODSEC-LINE-1");
        assert!(rules[0].name.contains("MODSEC-LINE-1"), "default name embeds the id");
    }

    #[test]
    fn action_keywords_map_to_internal_actions() {
        for (keyword, expected) in [("deny", "block"), ("block", "block"), ("allow", "allow"), ("pass", "allow"), ("log", "log")] {
            let content = format!("SecRule ARGS \"@rx x\" \"id:1,{keyword}\"\n");
            let rules = parse(&content).unwrap();
            assert_eq!(rules[0].action, expected, "{keyword} maps to {expected}");
        }
    }

    #[test]
    fn operator_variants_are_recognised() {
        for (op, expected_name, expected_value) in [
            ("@contains foo", "contains", "foo"),
            ("@beginsWith /api", "beginsWith", "/api"),
            ("@endsWith .php", "endsWith", ".php"),
            ("@ipMatch 10.0.0.0/8", "ipMatch", "10.0.0.0/8"),
            ("bare-pattern", "regex", "bare-pattern"),
        ] {
            let content = format!("SecRule ARGS \"{op}\" \"id:1,deny\"\n");
            let rules = parse(&content).unwrap();
            assert_eq!(rules[0].metadata.get("operator").map(String::as_str), Some(expected_name));
            assert_eq!(rules[0].pattern.as_deref(), Some(expected_value));
        }
    }

    #[test]
    fn category_is_inferred_from_pattern_then_variables() {
        for (variables, pattern, expected) in [
            ("REQUEST_HEADERS", "union all select", "sqli"),
            ("REQUEST_HEADERS", "<script>alert(1)", "xss"),
            ("REQUEST_HEADERS", "../etc/passwd", "traversal"),
            ("REQUEST_URI", "benign", "path"),
            ("ARGS", "benign", "input"),
            ("REQUEST_HEADERS", "benign", "custom"),
        ] {
            let content = format!("SecRule {variables} \"@contains {pattern}\" \"id:1,deny\"\n");
            let rules = parse(&content).unwrap();
            assert_eq!(rules[0].category, expected, "{variables} + {pattern}");
        }
    }

    #[test]
    fn metadata_captures_phase_status_severity_and_msg() {
        let content =
            "SecRule REQUEST_URI \"@rx /x\" \"id:7,phase:2,deny,status:403,severity:CRITICAL,msg:'Named rule'\"\n";
        let rules = parse(content).unwrap();
        let rule = &rules[0];
        assert_eq!(rule.metadata.get("phase").map(String::as_str), Some("2"));
        assert_eq!(rule.metadata.get("status").map(String::as_str), Some("403"));
        assert_eq!(rule.severity.as_deref(), Some("CRITICAL"));
        assert_eq!(rule.name, "Named rule");
        assert_eq!(rule.description.as_deref(), Some("Named rule"));
        assert_eq!(rule.source, "modsec");
        assert!(rule.enabled);
        assert_eq!(rule.tags, vec!["modsec".to_string()]);
    }

    #[test]
    fn continuation_backslash_at_eof_still_parses() {
        let content = "SecRule ARGS \"@rx x\" \\";
        let rules = parse(content).unwrap();
        assert!(rules.is_empty(), "incomplete rule (no actions) is skipped, not fatal");

        let complete = "SecRule ARGS \\\n\"@rx x\" \\\n\"id:5,deny\" \\";
        let rules = parse(complete).unwrap();
        assert_eq!(rules.len(), 1, "trailing backslash on the final line is flushed");
        assert_eq!(rules[0].id, "MODSEC-5");
    }

    #[test]
    fn non_secrule_directives_are_ignored() {
        let content = "SecDefaultAction \"phase:1,log\"\nSecComponentSignature \"x\"\n";
        let rules = parse(content).unwrap();
        assert!(rules.is_empty());
    }
}
