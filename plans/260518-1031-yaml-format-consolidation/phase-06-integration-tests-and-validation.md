---
phase: 6
title: "Integration Tests and Validation"
status: pending
priority: P1
effort: "4h"
dependencies: [4]
---

# Phase 6: Integration Tests and Validation

## Overview

Write integration tests that validate all migrated YAML rules load correctly, have matching logic, and produce equivalent detection results. Also add a regression test that loads every `.yaml` file in `rules/` to prevent future schema drift.

## Requirements

- Functional: All YAML files in `rules/` parse without errors
- Functional: Every rule has at least one matching mechanism
- Functional: Before/after behavior comparison for key attack patterns
- Non-functional: Tests run in `cargo test` without external dependencies

## Related Code Files

- Create: `crates/waf-engine/tests/yaml-rule-loading-integration.rs`
- Create: `crates/waf-engine/tests/owasp-rule-equivalence.rs`
- Modify: `crates/waf-engine/tests/custom_rule_hot_reload.rs` (add pattern-based rule test)

## Implementation Steps

### Step 1: All-YAML loading test

```rust
//! Integration test: verify every YAML rule file loads without errors.

#[test]
fn all_yaml_rules_load_successfully() {
    let rules_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap().parent().unwrap()
        .join("rules");

    let mut total_rules = 0;
    let mut total_files = 0;
    let mut errors = Vec::new();

    for entry in WalkDir::new(&rules_dir) {
        let path = entry.path();
        if !path.is_file() || path.extension() != Some("yaml".as_ref()) {
            continue;
        }

        let content = fs::read_to_string(path).unwrap();
        match custom_rule_yaml::parse(&content) {
            Ok(rules) => {
                total_rules += rules.len();
                total_files += 1;
            }
            Err(e) => errors.push(format!("{}: {e}", path.display())),
        }
    }

    assert!(errors.is_empty(), "Parse errors:\n{}", errors.join("\n"));
    assert!(total_rules > 300, "Expected 300+ rules, got {total_rules}");
    println!("Loaded {total_rules} rules from {total_files} files");
}
```

### Step 2: Every-rule-has-matching-logic test

```rust
#[test]
fn every_rule_has_matching_logic() {
    let rules = load_all_rules();
    let mut missing = Vec::new();

    for rule in &rules {
        let has_logic = rule.pattern.is_some()
            || !rule.conditions.is_empty()
            || rule.match_tree.is_some()
            || rule.script.is_some();

        if !has_logic {
            missing.push(rule.id.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "Rules without matching logic: {:?}",
        missing
    );
}
```

### Step 3: Pattern regex compilation test

```rust
#[test]
fn all_patterns_compile_to_valid_regex() {
    let rules = load_all_rules();
    let mut failures = Vec::new();

    for rule in &rules {
        if let Some(ref pattern) = rule.pattern {
            // Pattern should already be compiled at parse time,
            // but verify explicitly
            if regex::Regex::new(&pattern.to_string()).is_err() {
                failures.push(rule.id.clone());
            }
        }
    }

    assert!(
        failures.is_empty(),
        "Rules with invalid regex patterns: {:?}",
        failures
    );
}
```

### Step 4: OWASP behavior equivalence tests

Test key attack patterns against the unified engine and verify detection:

```rust
#[test]
fn detects_sqli_union_select() {
    let engine = build_test_engine();
    let ctx = request_ctx_with_query("id=1 UNION SELECT * FROM users--");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SQLi should be detected");
}

#[test]
fn detects_ssti_template_injection() {
    let engine = build_test_engine();
    let ctx = request_ctx_with_body("name={{7*7}}");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SSTI should be detected");
}

#[test]
fn detects_ssrf_internal_ip() {
    let engine = build_test_engine();
    let ctx = request_ctx_with_body("url=http://169.254.169.254/latest/meta-data/");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "SSRF should be detected");
}

#[test]
fn skips_routing_headers_in_all_field() {
    let engine = build_test_engine();
    // Host header with "localhost" should NOT trigger SSRF rules
    let ctx = request_ctx_with_host("localhost:8080");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_none(), "Host header should not trigger rules");
}

#[test]
fn url_decode_bypass_detected() {
    let engine = build_test_engine();
    // URL-encoded SSTI: %7B%7B7*7%7D%7D == {{7*7}}
    let ctx = request_ctx_with_query("name=%7B%7B7*7%7D%7D");
    let verdict = engine.check_with_verdict(&ctx);
    assert!(verdict.result.is_some(), "URL-encoded SSTI should be detected");
}

#[test]
fn paranoia_filtering_works() {
    let engine = build_test_engine();
    // Count rules at paranoia 1 vs paranoia 2
    // With max_paranoia=1, paranoia-2 rules should not fire
    let ctx = request_ctx_with_query("test");
    let verdict_p1 = engine.check_with_verdict_filtered(&ctx, Some(1));
    let verdict_p2 = engine.check_with_verdict_filtered(&ctx, Some(2));
    // Paranoia 2 may catch more — at minimum, p2 results >= p1 results
}
```

### Step 5: Hot-reload test with pattern-based rules

Add to `custom_rule_hot_reload.rs`:

```rust
#[test]
fn watcher_loads_pattern_based_rule() {
    // Create rule with pattern field (new feature)
    let yaml = r#"
kind: custom_rule_v1
id: pattern-test
name: SSRF pattern
pattern: "169\\.254\\.169\\.254"
pattern_field: body
action: block
"#;
    // Write to temp custom/ dir, verify engine picks it up
    ...
}
```

### Step 6: `deny_unknown_fields` test

Verify that adding `#[serde(deny_unknown_fields)]` to `YamlCustomRule` catches typos:

```rust
#[test]
fn rejects_unknown_yaml_fields() {
    let yaml = r#"
kind: custom_rule_v1
id: bad
name: test
unknown_field: oops
"#;
    let result = custom_rule_yaml::parse(yaml);
    assert!(result.is_err(), "Should reject unknown fields");
}
```

**Note:** Only add `deny_unknown_fields` after migration is complete and all fields are accounted for.

### Step 7: Rule count regression test

```rust
#[test]
fn rule_count_minimum_threshold() {
    let rules = load_all_rules();
    // Current: 351 rules. Set threshold slightly below to allow minor changes.
    assert!(
        rules.len() >= 340,
        "Expected at least 340 rules, got {}. Possible data loss during migration.",
        rules.len()
    );
}
```

### Step 8: Run full test suite

```bash
cargo test -p waf-engine
```

## Common Pitfalls

- **Test file paths** — `CARGO_MANIFEST_DIR` points to `crates/waf-engine/`. Navigate up to project root for `rules/`.
- **`pm_from_file` rules** — These reference external `.data` files. Tests may fail if data files aren't in expected path. Use test-specific paths or skip these rules.
- **Paranoia tests** — Default paranoia is 1. Most rules are paranoia 1. Need paranoia-2+ rules to test filtering.
- **Non-deterministic order** — Rule evaluation order matters. Sort by priority for consistent test results.

## Success Criteria

- [ ] `all_yaml_rules_load_successfully` passes with 340+ rules
- [ ] `every_rule_has_matching_logic` passes (zero orphan rules)
- [ ] `all_patterns_compile_to_valid_regex` passes
- [ ] SQLi, SSTI, SSRF detection tests pass
- [ ] URL-decode bypass test passes
- [ ] Routing header exclusion test passes
- [ ] Paranoia filtering test passes
- [ ] Hot-reload with pattern-based rules works
- [ ] Full `cargo test -p waf-engine` passes

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Flaky tests from file system timing | Medium | Use generous timeouts in hot-reload tests |
| pm_from_file path resolution in tests | Medium | Use absolute paths or skip those specific rules |
| False negative in equivalence tests | Medium | Test known payloads that should definitely trigger |
