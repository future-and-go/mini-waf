---
phase: 1
title: "Extend CustomRule Struct"
status: done
priority: P1
effort: "4h"
dependencies: []
---

# Phase 1: Extend CustomRule Struct

## Overview

Add Registry-specific fields (pattern, field, category, severity, paranoia, tags, metadata, reference) to both `YamlCustomRule` (wire DTO) and `CustomRule` (engine struct). This gives custom_rule_v1 format feature parity with both the Registry format and OWASPCheck's RuleSet.

## Requirements

- Functional: CustomRule must accept all fields present in Registry YAML files AND OWASPCheck's RuleSet
- Non-functional: Zero impact on existing custom rule parsing (all new fields are `serde(default)`)

## Architecture

`YamlCustomRule` gains new optional fields → `to_custom_rule()` maps them → `CustomRule` stores compiled Regex for pattern.

The `field` approach reuses OWASPCheck's proven targeting: `"all"`, `"path"`, `"query"`, `"body"`, `"method"`, `"content_length"`, `"cookies"`, `"headers"`, etc. Default: `"all"`.

## Related Code Files

- Modify: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` (lines 18-48, 107-124)
- Modify: `crates/waf-engine/src/rules/engine.rs` (lines 229-250)

## Implementation Steps

### Step 1: Extend `YamlCustomRule` in `custom_rule_yaml.rs`

Add after existing fields (line ~47):

```rust
// --- NEW: Registry/OWASP compatibility fields ---

/// Regex pattern string. Evaluated against the field specified by `pattern_field`.
/// When present without conditions/match_tree, acts as the matching logic.
#[serde(default)]
pattern: Option<String>,

/// Which request field to check pattern against.
/// Values: "all", "path", "query", "body", "method", "headers", "cookies"
/// Default: "all" (matches path+query+body+non-routing-headers).
#[serde(default = "default_field")]
pattern_field: String,

/// Operator when using field+operator+value shorthand (Registry format).
/// Values: "regex", "contains", "eq", "starts_with", "ends_with", etc.
#[serde(default)]
operator: Option<String>,

/// Value for the operator shorthand. Can be string, list, or number.
#[serde(default)]
value: Option<serde_yaml::Value>,

/// Rule category: sqli, xss, rce, ssti, ssrf, etc.
#[serde(default)]
category: Option<String>,

/// Severity: critical, high, medium, low.
#[serde(default)]
severity: Option<String>,

/// OWASP CRS paranoia level (1-4). Metadata only — stored for filtering.
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
```

Add the default function:

```rust
fn default_field() -> String {
    "all".to_string()
}
```

### Step 2: Extend `CustomRule` in `engine.rs`

Add after existing fields (line ~249):

```rust
/// Pre-compiled regex pattern. Evaluated against `pattern_field`.
pub pattern: Option<Regex>,

/// Which request field the pattern targets.
pub pattern_field: String,

/// Rule category (sqli, xss, ssti, etc.)
pub category: Option<String>,

/// Severity level (critical, high, medium, low)
pub severity: Option<String>,

/// OWASP CRS paranoia level (1-4). Metadata only.
pub paranoia: Option<u8>,

/// Tags for filtering/grouping.
pub tags: Vec<String>,

/// Arbitrary metadata key-value pairs.
pub metadata: HashMap<String, String>,

/// External reference URL.
pub reference: Option<String>,
```

### Step 3: Update `to_custom_rule()` mapping

In `custom_rule_yaml.rs`, update the conversion function:

```rust
fn to_custom_rule(dto: YamlCustomRule) -> Result<CustomRule> {
    // Compile regex pattern if present
    let pattern = match &dto.pattern {
        Some(p) => Some(Regex::new(p).with_context(|| format!("invalid pattern regex: {p}"))?),
        None => None,
    };

    Ok(CustomRule {
        // ... existing fields unchanged ...
        pattern,
        pattern_field: dto.pattern_field,
        category: dto.category,
        severity: dto.severity,
        paranoia: dto.paranoia,
        tags: dto.tags,
        metadata: dto.metadata,
        reference: dto.reference,
    })
}
```

**Note:** `to_custom_rule` changes return type from `CustomRule` to `Result<CustomRule>` because regex compilation can fail. Update `parse()` call site to propagate.

### Step 4: Add `HashMap` import and `Regex` import

- `engine.rs`: add `use std::collections::HashMap;` and `use regex::Regex;` (check if already imported)
- `custom_rule_yaml.rs`: add `use std::collections::HashMap;`

### Step 5: Update `RuleEntry::from_rule_with_source` and Clone

Since `CustomRule` now contains `Regex` (which implements `Clone`), ensure `#[derive(Clone)]` still works. `regex::Regex` implements `Clone` so this should be fine.

### Step 6: Run `cargo check`

Verify compilation. Fix any missing field initializations in tests or other constructors of `CustomRule`.

## Common Pitfalls

- **Forgetting `serde(default)` on new fields** — breaks existing YAML files that don't have these fields
- **`Regex` in struct** — needs `regex` crate import in `engine.rs`; verify Clone/Debug
- **`to_custom_rule` signature change** — every call site in `parse()` must handle the `Result`
- **HashMap import** — `std::collections::HashMap` not `serde_yaml::Mapping`

## Success Criteria

- [x] `YamlCustomRule` has pattern, pattern_field, operator, value, category, severity, paranoia, tags, metadata, reference fields
- [x] `CustomRule` has matching fields with pre-compiled `Option<Regex>` for pattern
- [x] `to_custom_rule()` compiles regex at parse time with 1MB DFA size limit
- [x] All existing tests pass (126 rules unit tests + 17 acceptance tests)
- [x] `cargo check` passes with zero warnings
- [x] Bench file (rule_eval.rs) updated too

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Breaking existing YAML parsing | High | All new fields use `serde(default)` |
| Regex compilation panic | Medium | Use `Result` return, never `.unwrap()` |
| `CustomRule` size bloat | Low | All new fields are small (Option<String>, Vec<String>) |
