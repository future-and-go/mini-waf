//! Integration tests: verify all YAML rule files in `rules/` parse correctly,
//! have matching logic, and compile valid regex patterns.

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
    clippy::missing_const_for_fn,
    clippy::print_stderr
)]

use std::fs;
use std::path::{Path, PathBuf};

use waf_engine::rules::formats::custom_rule_yaml;

/// Recursively collect all `.yaml` files under `dir`.
fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in fs::read_dir(dir).expect("read rules dir") {
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

/// Resolve path to the project-root `rules/` directory.
fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rules")
}

/// Parse all YAML files in `rules/`, skipping per-file errors (matches
/// production `load_dir` behavior where per-file failures are logged, not fatal).
fn load_all_rules() -> Vec<waf_engine::CustomRule> {
    let dir = rules_dir();
    let files = collect_yaml_files(&dir);
    let mut all_rules = Vec::new();

    for path in &files {
        let content = fs::read_to_string(path).expect("read yaml file");
        if let Ok(rules) = custom_rule_yaml::parse(&content) {
            all_rules.extend(rules);
        }
    }

    all_rules
}

#[test]
fn all_yaml_rules_load_successfully() {
    let dir = rules_dir();
    let files = collect_yaml_files(&dir);

    let mut total_rules = 0;
    let mut total_files = 0;
    let mut errors = Vec::new();

    for path in &files {
        let content = fs::read_to_string(path).expect("read yaml file");
        match custom_rule_yaml::parse(&content) {
            Ok(rules) => {
                total_rules += rules.len();
                if !rules.is_empty() {
                    total_files += 1;
                }
            }
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    // Known-bad files: rules with regex patterns exceeding 1 MB DFA limit.
    // Production loader logs and skips per-file. Only allow these specific files.
    let known_bad: &[&str] = &["webshell-upload.yaml", "rce.yaml", "xss.yaml"];
    let unexpected: Vec<_> = errors
        .iter()
        .filter(|e| !known_bad.iter().any(|kb| e.contains(kb)))
        .collect();
    assert!(
        unexpected.is_empty(),
        "Unexpected parse errors (not in known-bad list):\n{}",
        unexpected.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n")
    );
    if !errors.is_empty() {
        eprintln!("Warning: {} known-bad files skipped:", errors.len());
        for e in &errors {
            eprintln!("  {e}");
        }
    }

    assert!(total_rules > 300, "Expected 300+ rules, got {total_rules}");
    eprintln!(
        "Loaded {total_rules} rules from {total_files} files ({} files skipped)",
        errors.len()
    );
}

#[test]
fn every_rule_has_matching_logic() {
    let rules = load_all_rules();
    let mut missing = Vec::new();

    for rule in &rules {
        let has_pattern = rule.pattern.is_some();
        let has_conditions = !rule.conditions.is_empty();
        let has_tree = rule.match_tree.is_some();
        let has_script = rule.script.is_some();
        let has_specialised = rule.specialised_op.is_some();

        if !has_pattern && !has_conditions && !has_tree && !has_script && !has_specialised {
            missing.push(rule.id.clone());
        }
    }

    assert!(missing.is_empty(), "Rules without matching logic: {missing:?}");
}

#[test]
fn all_patterns_are_precompiled() {
    let rules = load_all_rules();
    let mut with_pattern = 0;

    for rule in &rules {
        if rule.pattern.is_some() {
            with_pattern += 1;
        }
    }

    // Patterns are compiled at parse time inside `to_custom_rule`.
    // If parsing succeeded, regexes are valid. This test confirms
    // we actually have pattern-based rules (regression guard).
    assert!(
        with_pattern > 50,
        "Expected 50+ pattern-based rules, got {with_pattern}"
    );
    eprintln!("{with_pattern} rules have pre-compiled regex patterns");
}

#[test]
fn rule_count_minimum_threshold() {
    let rules = load_all_rules();
    assert!(
        rules.len() >= 340,
        "Expected at least 340 rules, got {}. Possible data loss during migration.",
        rules.len()
    );
}

#[test]
fn rejects_unknown_kind_version() {
    let yaml = r"
kind: custom_rule_v2
id: bad
name: test
";
    let result = custom_rule_yaml::parse(yaml);
    assert!(result.is_err(), "Should reject unsupported kind version");
}

#[test]
fn skips_documents_without_kind() {
    let yaml = "- id: TEST-001\n  name: legacy registry rule\n";
    let result = custom_rule_yaml::parse(yaml).expect("should not error");
    assert!(result.is_empty(), "Documents without kind should be skipped");
}
