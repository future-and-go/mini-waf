# Code Review: Rule Engine Module — YAML Format Support

**Date:** 2026-05-16  
**Reviewer:** Claude Code  
**Scope:** `crates/waf-engine/src/rules/` — YAML format compliance for all rule types  
**Request:** Verify all rules support YAML format

---

## Executive Summary

**Overall Assessment: CRITICAL ISSUES FOUND**

The rule engine has **two distinct YAML formats** that are **incompatible**:

1. **Registry Rules** (`Rule` struct) — parsed by `formats/yaml.rs`
2. **Custom Rules** (`CustomRule` struct) — parsed by `formats/custom_rule_yaml.rs`

The documented YAML schema in `rules/README.md` does NOT match the parser implementation, causing **silent data loss** when loading rule files.

---

## Critical Findings

### 1. CRITICAL: Schema Mismatch Between Documentation and Parser

**Severity:** CRITICAL  
**Location:** `formats/yaml.rs` vs `rules/README.md` and actual YAML files

**Problem:**  
The YAML files in `rules/` (e.g., `example.yaml`, `ssrf.yaml`) use this schema:

```yaml
version: "1.0"
description: "..."
rules:
  - id: "ADV-SSRF-001"
    field: "all"           # NOT in parser
    operator: "regex"      # NOT in parser
    value: "(?i)10\\..*"   # NOT in parser
    paranoia: 1            # NOT in parser
    reference: "https://..." # NOT in parser
```

But `YamlRule` struct only has:
```rust
struct YamlRule {
    id: String,
    name: String,
    description: Option<String>,
    category: String,
    source: String,
    enabled: bool,
    action: String,
    severity: Option<String>,
    pattern: Option<String>,  // Uses 'pattern', not 'field/operator/value'
    tags: Vec<String>,
    metadata: HashMap<String, String>,
    // Missing: field, operator, value, paranoia, reference
}
```

**Impact:**  
- 84 YAML files in `rules/` directory use undocumented fields
- Fields `field`, `operator`, `value`, `paranoia`, `reference` are **silently ignored**
- Rules load with empty patterns, rendering them non-functional
- No error is raised — serde ignores unknown fields by default

**Evidence:**
```bash
$ grep -c "field:" rules/advanced/*.yaml rules/custom/example.yaml
rules/advanced/ssti.yaml:13
rules/advanced/ssrf.yaml:15
rules/custom/example.yaml:7
# ... total 84+ occurrences
```

**Recommendation:**  
Add missing fields to `YamlRule` or add `#[serde(deny_unknown_fields)]` to catch mismatches.

---

### 2. HIGH: Wrapper Structure Not Parsed

**Severity:** HIGH  
**Location:** `formats/yaml.rs:55-56`

**Problem:**  
Parser expects direct array: `[{id: ..., name: ...}, ...]`  
YAML files have wrapper: `{version: ..., rules: [{...}]}`

```rust
// Current parser
pub fn parse(content: &str) -> Result<Vec<Rule>> {
    let raw: Vec<YamlRule> = serde_yaml::from_str(content)?;  // Expects array
    // ...
}
```

**Impact:**  
Files with wrapper structure fail to parse entirely.

**Recommendation:**  
Add wrapper struct to handle top-level `version`, `description`, `source`, `license`, `rules` fields.

---

### 3. MEDIUM: Regex Recompilation in Fallback Path

**Severity:** MEDIUM  
**Location:** `engine.rs:525`

**Problem:**  
When compiled rule entry is `None` (compile failed), fallback path recompiles regex on every request:

```rust
(Operator::Regex, ConditionValue::Str(v)) => 
    Regex::new(v).ok().is_some_and(|r| r.is_match(fstr)),  // Per-request compile
```

**Impact:**  
Performance degradation in error recovery path. ReDoS potential if malicious regex is evaluated repeatedly.

**Mitigating Factor:**  
Main path uses pre-compiled `CompiledRule` with `Matcher::Regex(Regex)`. Fallback only triggers when `compile_rule()` fails.

**Recommendation:**  
Log warning when fallback is triggered; consider caching failed regex compilation result.

---

## Good Practices Found

### Resource Limits (GOOD)

```rust
// Rhai script sandbox — engine.rs:331-333
engine.set_max_operations(100_000);
engine.set_max_call_levels(16);
engine.set_max_expr_depths(64, 32);

// Condition tree limits — engine.rs:630-633
pub const MAX_TREE_DEPTH: usize = 16;
pub const MAX_TREE_LEAVES: usize = 256;
```

### CustomRule YAML Parser (GOOD)

`custom_rule_yaml.rs` correctly handles:
- `kind: custom_rule_v1` discriminator for version safety
- Multi-document YAML streams
- Forward compatibility rejection (`custom_rule_v999` errors)
- Nested `match_tree` with AND/OR/NOT logic
- Cookie newtype fields `{cookie: session}`

### Pre-compiled Matchers (GOOD)

`CompiledRule` pre-compiles all matchers at load time:
- Regex patterns → `Matcher::Regex(Regex)`
- Glob/wildcard → `Matcher::Glob(GlobMatcher)`
- CIDR ranges → `Matcher::Cidr(ipnet::IpNet)`
- Lists → `Matcher::InList(AHashSet)`

---

## Security Analysis

| Risk | Status | Notes |
|------|--------|-------|
| ReDoS | LOW | Regex compiled at load time with error handling; fallback path is edge case |
| Path Traversal | SAFE | `custom_file_loader.rs` only reads from configured `rules_root/custom/` |
| OOM from Large Files | LOW | Remote sources capped at 10MB; local files not capped (acceptable) |
| SSRF in Remote Rules | SAFE | `validate_public_url_with_ips()` validates URLs, DNS pinning applied |
| Rhai Script Injection | SAFE | Sandbox limits in place |

---

## Recommendations

### Immediate (P0)

1. **Fix `YamlRule` struct** — Add `field`, `operator`, `value`, `paranoia`, `reference` fields
2. **Add wrapper parsing** — Handle `{version, description, rules: [...]}` structure
3. **Add `#[serde(deny_unknown_fields)]`** to catch schema mismatches during development

### Short-term (P1)

4. **Add integration test** that loads actual `rules/*.yaml` files and verifies patterns are populated
5. **Log warning** when legacy `eval_conditions()` fallback is triggered
6. **Document** the two YAML formats clearly (Registry vs CustomRule)

### Long-term (P2)

7. **Unify formats** — Consider migrating Registry rules to CustomRule format for consistency
8. **Add regex complexity check** — Reject pathological patterns at load time

---

## Files Reviewed

| File | Lines | Status |
|------|-------|--------|
| `formats/mod.rs` | 249 | OK |
| `formats/yaml.rs` | 125 | **CRITICAL issues** |
| `formats/json.rs` | 97 | OK (same schema issue) |
| `formats/modsec.rs` | 259 | OK |
| `formats/custom_rule_yaml.rs` | 297 | GOOD |
| `engine.rs` | 1400+ | GOOD (minor fallback issue) |
| `manager.rs` | 658 | OK |
| `registry.rs` | 310 | OK |
| `custom_file_loader.rs` | 227 | GOOD |
| `builtin/*.rs` | ~300 | GOOD (hardcoded, no YAML) |

---

## Conclusion

The CustomRule YAML format (`kind: custom_rule_v1`) is **well-implemented** and supports all documented features including nested conditions and match trees.

However, the Registry Rule YAML format has a **critical schema mismatch** that silently ignores the `field`, `operator`, and `value` fields used in 84+ rule files. This renders those rule files non-functional.

**Action Required:** Fix `YamlRule` struct before relying on `rules/*.yaml` files in production.

---

## Unresolved Questions

1. Are the `rules/advanced/*.yaml` and `rules/owasp-crs/*.yaml` files currently used in production, or are they documentation/examples only?
2. Is the intent to use Registry Rules format or should everything migrate to CustomRule format?
3. Should there be a migration path from existing YAML files to the correct schema?
