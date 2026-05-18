---
phase: 3
title: "Migration Script"
status: done
priority: P1
effort: "4h"
dependencies: [1]
---

# Phase 3: Migration Script

## Overview

Write a Rust binary to convert all 351 Registry-format YAML rules (in `rules/advanced/`, `rules/owasp-crs/`, `rules/cve-patches/`, `rules/bot-detection/`) into `custom_rule_v1` format. Output replaces the original files in-place so existing directory structure is preserved.

## Requirements

- Functional: Every rule in every `.yaml` file under `rules/` (except `rules/custom/`) is converted
- Functional: Pattern + field preserved; operator/value + field converted to conditions when not regex
- Functional: Metadata (category, severity, paranoia, tags, reference, risk_delta, risk_action, crs_id) preserved
- Non-functional: Rule count before == rule count after (validated by script)

## Architecture

The script reads the Registry wrapper format `{version, rules: [...]}`, iterates each rule, and emits multi-document YAML (`---` separated) in `custom_rule_v1` format.

```
Input:  rules/advanced/ssti.yaml (wrapper with rules array)
Output: rules/advanced/ssti.yaml (multi-doc custom_rule_v1)
```

## Related Code Files

- Create: `scripts/migrate-yaml-rules.rs` (standalone Rust script, `cargo-script` or `scripts/` bin)
- Read: `crates/waf-engine/src/rules/formats/yaml.rs` (Registry YamlRule struct — reference)
- Read: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` (target format — reference)
- Modify: `rules/advanced/*.yaml`, `rules/owasp-crs/*.yaml`, `rules/cve-patches/*.yaml`, `rules/bot-detection/*.yaml`

## Implementation Steps

### Step 1: Define source struct (Registry wrapper format)

```rust
#[derive(Debug, Deserialize)]
struct RegistryWrapper {
    #[serde(default)]
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    source: String,
    #[serde(default)]
    license: String,
    rules: Vec<RegistryRule>,
}

#[derive(Debug, Deserialize)]
struct RegistryRule {
    id: String,
    name: String,
    #[serde(default)]
    category: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    paranoia: Option<u8>,
    #[serde(default)]
    field: String,          // "all", "path", "method", "content_length", etc.
    #[serde(default)]
    operator: String,       // "regex", "contains", "not_in", "gt", etc.
    #[serde(default)]
    value: serde_yaml::Value, // String, List, or Number
    #[serde(default)]
    action: String,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    risk_delta: Option<i16>,
    #[serde(default)]
    risk_action: Option<String>,
    #[serde(default)]
    reference: Option<String>,
    #[serde(default)]
    crs_id: Option<u32>,
    #[serde(default)]
    metadata: HashMap<String, String>,
}
```

### Step 2: Define target output struct

```rust
#[derive(Debug, Serialize)]
struct OutputRule {
    kind: String,           // always "custom_rule_v1"
    id: String,
    name: String,
    #[serde(skip_serializing_if = "is_default_host")]
    host_code: String,      // always "*"
    #[serde(skip_serializing_if = "is_zero")]
    priority: i32,
    enabled: bool,
    action: String,         // "block", "log", "allow"

    // Pattern path: when operator is "regex" and field is specified
    #[serde(skip_serializing_if = "Option::is_none")]
    pattern: Option<String>,
    #[serde(skip_serializing_if = "is_default_field")]
    pattern_field: String,

    // Condition path: when operator is NOT regex
    #[serde(skip_serializing_if = "Vec::is_empty")]
    conditions: Vec<OutputCondition>,

    // Metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    paranoia: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_delta: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    risk_action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    metadata: HashMap<String, String>,
}
```

### Step 3: Conversion logic

```rust
fn convert_rule(r: RegistryRule, wrapper_source: &str) -> OutputRule {
    let is_regex = r.operator == "regex";
    let is_pm = r.operator == "pm_from_file";

    // Regex rules → pattern field
    // Other operators → conditions
    let (pattern, conditions) = if is_regex {
        (yaml_value_to_string(&r.value), vec![])
    } else if is_pm {
        // pm_from_file stays as pattern (handled by plugin system)
        (yaml_value_to_string(&r.value), vec![])
    } else {
        (None, vec![build_condition(&r)])
    };

    let mut metadata = r.metadata;
    if let Some(crs_id) = r.crs_id {
        metadata.insert("crs_id".to_string(), crs_id.to_string());
    }
    if !wrapper_source.is_empty() {
        metadata.insert("source".to_string(), wrapper_source.to_string());
    }

    OutputRule {
        kind: "custom_rule_v1".to_string(),
        id: r.id,
        name: r.name,
        host_code: "*".to_string(),
        priority: 0,
        enabled: true,
        action: if r.action.is_empty() { "block".to_string() } else { r.action },
        pattern,
        pattern_field: if r.field.is_empty() { "all".to_string() } else { r.field },
        conditions,
        category: if r.category.is_empty() { None } else { Some(r.category) },
        severity: if r.severity.is_empty() { None } else { Some(r.severity) },
        paranoia: r.paranoia,
        tags: r.tags,
        risk_delta: r.risk_delta,
        risk_action: r.risk_action,
        reference: r.reference,
        metadata,
    }
}
```

### Step 4: File walker and writer

```rust
fn migrate_directory(dir: &Path, stats: &mut Stats) -> Result<()> {
    for entry in WalkDir::new(dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if !path.is_file() || path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        // Skip custom/ directory (already in v1 format)
        if path.to_string_lossy().contains("/custom/") {
            continue;
        }
        migrate_file(path, stats)?;
    }
    Ok(())
}

fn migrate_file(path: &Path, stats: &mut Stats) -> Result<()> {
    let content = fs::read_to_string(path)?;

    // Try wrapper format first (version + rules array)
    let wrapper: RegistryWrapper = match serde_yaml::from_str(&content) {
        Ok(w) => w,
        Err(_) => {
            // Try flat array format
            let rules: Vec<RegistryRule> = serde_yaml::from_str(&content)?;
            RegistryWrapper { rules, ..Default::default() }
        }
    };

    let rules_before = wrapper.rules.len();
    let mut output = String::new();

    for rule in wrapper.rules {
        let converted = convert_rule(rule, &wrapper.source);
        if !output.is_empty() {
            output.push_str("---\n");
        }
        output.push_str(&serde_yaml::to_string(&converted)?);
    }

    fs::write(path, &output)?;
    stats.files += 1;
    stats.rules_before += rules_before;
    stats.rules_after += /* count "kind:" lines in output */;
    Ok(())
}
```

### Step 5: Validation pass

After migration, verify:

```rust
fn validate(dir: &Path) -> Result<()> {
    let mut total = 0;
    for entry in WalkDir::new(dir) ... {
        let content = fs::read_to_string(path)?;
        let rules = custom_rule_yaml::parse(&content)?;
        total += rules.len();
        for rule in &rules {
            // Verify every rule has matching logic
            assert!(
                rule.pattern.is_some() || !rule.conditions.is_empty() || rule.match_tree.is_some(),
                "Rule {} has no matching logic", rule.id
            );
        }
    }
    println!("Validated {total} rules across all files");
    Ok(())
}
```

### Step 6: Run migration

```bash
cargo run --bin migrate-yaml-rules -- rules/
```

### Step 7: Git diff review

Manually review `git diff rules/` to verify no logic changes, no lost fields.

## Common Pitfalls

- **`pm_from_file` operator** — references external data files. Keep as `pattern` field; the OWASP check has special handling for this.
- **Value types** — Registry YAML has `value` as string, list, OR number. Must handle all three.
- **Multi-doc output** — Use `---` separator between documents. First doc doesn't need `---` prefix.
- **YAML special chars in regex** — Patterns with brackets/quotes need proper YAML escaping. Use serde_yaml to handle this.
- **Empty operator** — Some rules only have `pattern:` without operator. These are regex by convention.

## Success Criteria

- [x] All 40 YAML files migrated (6 advanced + 24 owasp-crs + 7 cve-patches + 3 bot-detection)
- [x] Rule count preserved: 490 rules before == 490 rules after
- [x] Every migrated rule parseable by `custom_rule_yaml::parse()` (3 pre-existing regex warnings)
- [x] Every rule has at least one matching mechanism (pattern OR operator shorthand)
- [x] Metadata preserved: category, severity, paranoia, tags, risk_delta, crs_id (in metadata)
- [x] `git diff` review shows no unexpected changes
- [x] All 126 rules:: tests pass, full workspace compiles clean

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Silent field drops during conversion | High | Validate rule count + content diff review |
| Regex escaping corruption | Medium | Use serde_yaml serializer (handles escaping) |
| pm_from_file rules broken | Medium | Keep as pattern field; test separately |
| Rule logic changes | Medium | Before/after integration test comparison |
