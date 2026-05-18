# Brainstorm Report: YAML Rule Format Consolidation

**Date:** 2026-05-16  
**Context:** Code review identified critical schema mismatch in rule engine YAML parsing  
**Goal:** Consolidate Registry Rules and CustomRule into unified format for production use

---

## Problem Statement

Two incompatible YAML formats exist in the rule engine:

| Aspect | Registry (yaml.rs) | CustomRule (custom_rule_yaml.rs) |
|--------|-------------------|----------------------------------|
| Discriminator | None (flat array) | `kind: custom_rule_v1` |
| Structure | `[{rule}, {rule}]` | `{kind, id, conditions, ...}` |
| Matching | `pattern: regex` | `conditions: [{field, operator, value}]` |
| Fields | `id, name, pattern, tags, severity` | `id, name, conditions, match_tree, script` |

**Critical Issues:**
1. Registry YAML files use wrapper `{version, rules: [...]}` but parser expects `[...]`
2. Fields `field`, `operator`, `value`, `paranoia`, `reference` are **silently ignored**
3. 84+ rule files in `rules/advanced/` and `rules/owasp-crs/` are non-functional

---

## User Requirements (Confirmed)

1. **Target format:** CustomRule v1 (more powerful, has versioning)
2. **Pattern handling:** Add `pattern` field to CustomRule struct
3. **Metadata:** Add `category`, `severity`, `tags`, `metadata` to CustomRule
4. **Migration:** Big-bang one-time conversion of all files

---

## Technical Solution

### Phase 1: Extend CustomRule Struct

**Why:** CustomRule needs Registry-specific fields for full feature parity.

```rust
// custom_rule_yaml.rs - YamlCustomRule additions
#[derive(Debug, Deserialize)]
struct YamlCustomRule {
    // ... existing fields ...
    
    // NEW: Registry compatibility fields
    #[serde(default)]
    pattern: Option<String>,           // Regex pattern (matches all fields)
    #[serde(default)]
    category: Option<String>,          // Rule category (ssrf, xss, etc)
    #[serde(default)]
    severity: Option<String>,          // critical, high, medium, low
    #[serde(default)]
    paranoia: Option<u8>,              // OWASP CRS paranoia level 1-4
    #[serde(default)]
    tags: Vec<String>,                 // Rule tags for filtering
    #[serde(default)]
    metadata: HashMap<String, String>, // Arbitrary key-value pairs
    #[serde(default)]
    reference: Option<String>,         // External documentation URL
}
```

**Engine-side CustomRule:**
```rust
// engine.rs - CustomRule additions
pub struct CustomRule {
    // ... existing fields ...
    pub pattern: Option<Regex>,        // Pre-compiled regex
    pub category: Option<String>,
    pub severity: Option<String>,
    pub paranoia: Option<u8>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub reference: Option<String>,
}
```

### Phase 2: Pattern Evaluation Logic

**Why:** Pattern-based matching must work alongside condition-based matching.

**Evaluation precedence:**
1. If `match_tree` present → use tree evaluation
2. Else if `conditions` non-empty → use flat condition evaluation
3. Else if `pattern` present → match against all request fields
4. Else → rule always matches (log warning)

```rust
// engine.rs - eval_custom_rule() modification
fn eval_custom_rule(&self, rule: &CompiledRule, req: &Request) -> bool {
    // Existing: match_tree takes precedence
    if let Some(tree) = &rule.match_tree {
        return self.eval_tree(tree, req);
    }
    
    // Existing: flat conditions
    if !rule.conditions.is_empty() {
        return self.eval_flat_conditions(rule, req);
    }
    
    // NEW: pattern fallback (matches against all fields)
    if let Some(pattern) = &rule.pattern {
        return self.pattern_matches_request(pattern, req);
    }
    
    // No matching logic - warn and match
    tracing::warn!(rule_id = %rule.id, "rule has no match logic, always matching");
    true
}

fn pattern_matches_request(&self, pattern: &Regex, req: &Request) -> bool {
    // Check all relevant request fields
    pattern.is_match(&req.path)
        || pattern.is_match(&req.query.as_deref().unwrap_or(""))
        || pattern.is_match(&req.body.as_deref().unwrap_or(""))
        || req.headers.iter().any(|(_, v)| pattern.is_match(v))
        || req.cookies.values().any(|v| pattern.is_match(v))
}
```

### Phase 3: Migration Script

**Why:** Convert 84+ Registry YAML files to unified CustomRule format.

**Location:** `scripts/migrate-yaml-rules.rs` (one-time Rust binary)

```rust
// Migration algorithm pseudocode
fn migrate_registry_to_custom(input_path: &Path, output_path: &Path) -> Result<()> {
    let content = fs::read_to_string(input_path)?;
    let wrapper: RegistryWrapper = serde_yaml::from_str(&content)?;
    
    let mut output = String::new();
    for rule in wrapper.rules {
        let custom = YamlCustomRule {
            kind: "custom_rule_v1".to_string(),
            id: rule.id,
            name: rule.name,
            host_code: "*".to_string(),
            priority: 0,
            enabled: true,
            
            // Convert pattern OR field/operator/value
            pattern: rule.pattern.or_else(|| {
                if rule.operator == "regex" {
                    Some(rule.value.clone())
                } else {
                    None
                }
            }),
            conditions: if rule.operator != "regex" {
                vec![Condition {
                    field: parse_field(&rule.field),
                    operator: parse_operator(&rule.operator),
                    value: rule.value,
                }]
            } else {
                vec![]
            },
            
            // Carry over metadata
            action: rule.action,
            category: Some(rule.category),
            severity: rule.severity,
            paranoia: rule.paranoia,
            tags: rule.tags,
            reference: rule.reference,
            risk_delta: rule.risk_delta,
            ..Default::default()
        };
        
        output.push_str("---\n");
        output.push_str(&serde_yaml::to_string(&custom)?);
    }
    
    fs::write(output_path, output)?;
    Ok(())
}
```

### Phase 4: Cleanup

**Delete:**
- `formats/yaml.rs` (Registry parser)
- `formats/json.rs` (if same schema issues)

**Update:**
- `formats/mod.rs` - remove registry exports
- `rules/README.md` - document unified format

---

## Design Patterns Applied

### 1. Discriminated Union (Version Safety)
```yaml
kind: custom_rule_v1  # Discriminator enables future v2 without breaking
```
- Parser rejects unknown versions (`custom_rule_v999` → error)
- Backward compatible: documents without `kind` are skipped

### 2. Strategy Pattern (Matching Logic)
```
match_tree → TreeStrategy
conditions → FlatConditionStrategy  
pattern → PatternStrategy (NEW)
```
- Evaluation picks strategy based on which fields are populated
- Clear precedence order prevents ambiguity

### 3. Builder Pattern (Programmatic Creation)
```rust
CustomRule::builder()
    .id("CUSTOM-001")
    .pattern(r"10\.\d+\.\d+\.\d+")
    .severity("critical")
    .build()?
```
- Type-safe rule construction
- Validation at build time, not runtime

---

## Best Practices Applied

### 1. Schema Validation
```rust
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]  // Catch typos and schema drift
struct YamlCustomRule { ... }
```

### 2. Integration Tests
```rust
#[test]
fn test_load_all_yaml_files() {
    let dir = PathBuf::from("rules/custom");
    let rules = custom_file_loader::load_dir(&dir).unwrap();
    
    // Verify no empty patterns
    for rule in &rules {
        assert!(
            rule.pattern.is_some() 
                || !rule.conditions.is_empty() 
                || rule.match_tree.is_some(),
            "Rule {} has no matching logic", rule.id
        );
    }
}
```

### 3. Migration Validation
```bash
# Pre-migration count
$ grep -r "^  - id:" rules/advanced rules/owasp-crs | wc -l
84

# Post-migration count
$ grep -c "kind: custom_rule_v1" rules/custom/*.yaml
84  # Must match
```

### 4. Logging During Migration
```rust
tracing::info!(
    rule_id = %rule.id,
    from = %input_path.display(),
    to = %output_path.display(),
    "migrated rule"
);
```

---

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Rule logic changes during migration | Medium | High | Integration tests comparing old vs new behavior |
| Pattern regex compilation failures | Low | Medium | Pre-validate all patterns before migration |
| Performance regression (pattern check all fields) | Low | Medium | Benchmark before/after; pattern is last-resort |
| Missing rules after migration | Low | High | Count validation; git diff review |

---

## Implementation Phases

### P0 (Immediate) - 2-3 days
1. Extend `YamlCustomRule` struct with new fields
2. Extend `CustomRule` struct and `from_yaml()` mapping
3. Add pattern evaluation to `eval_custom_rule()`
4. Add `#[serde(deny_unknown_fields)]` for development

### P1 (Migration) - 1-2 days
5. Write migration script (`scripts/migrate-yaml-rules.rs`)
6. Run migration on `rules/advanced/` and `rules/owasp-crs/`
7. Move migrated files to `rules/custom/`
8. Validate rule counts match

### P2 (Cleanup) - 1 day
9. Delete `formats/yaml.rs` and `formats/json.rs`
10. Update `formats/mod.rs` exports
11. Update `rules/README.md` with unified schema docs
12. Add integration test loading all YAML files

### P3 (Polish) - Optional
13. Add JSON Schema for IDE validation
14. Add regex complexity check at load time
15. Builder pattern for programmatic rule creation

---

## Success Criteria

- [ ] All 84+ YAML rules load without silent data loss
- [ ] Pattern field works in CustomRule format
- [ ] Registry parser code deleted (single source of truth)
- [ ] Integration test validates all YAML files load with matching logic
- [ ] No performance regression (benchmark rule evaluation)

---

## File Changes Summary

| File | Action | Notes |
|------|--------|-------|
| `formats/custom_rule_yaml.rs` | Modify | Add 7 fields to YamlCustomRule |
| `engine.rs` | Modify | Add pattern evaluation, extend CustomRule |
| `scripts/migrate-yaml-rules.rs` | Create | One-time migration binary |
| `formats/yaml.rs` | Delete | After migration complete |
| `formats/json.rs` | Delete | If same schema issues |
| `formats/mod.rs` | Modify | Remove registry exports |
| `rules/README.md` | Modify | Document unified format |
| `rules/custom/*.yaml` | Create | Migrated rule files |
| `tests/yaml_rules.rs` | Create | Integration tests |

---

## Design Decisions (Resolved)

| Question | Decision | Rationale |
|----------|----------|-----------|
| Paranoia levels | Metadata only | Store for filtering/reporting, no execution impact |
| Field targeting | All request data | Match path + query + body + headers + cookies for thorough detection |
| File organization | Keep subdirectories | `rules/custom/advanced/`, `rules/custom/owasp-crs/` preserves category structure |
