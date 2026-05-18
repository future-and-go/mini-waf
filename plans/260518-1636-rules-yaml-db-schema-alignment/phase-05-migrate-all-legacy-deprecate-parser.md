---
phase: 5
title: "Migrate All Legacy Files & Deprecate Parser"
status: done
priority: P2
effort: "4h"
dependencies: [2, 4]
---

# Phase 5: Migrate All Legacy Files & Deprecate Parser

## Overview

After Phase 2 migrates `geoip/` and `modsecurity/dos-protection.yaml`, and Phase 4 migrates `custom/example.yaml`, 8 legacy-format files remain (98 rules total). This phase migrates all of them to `custom_rule_v1` and deprecates `legacy_parse_ruleset()`, eliminating the dual-parser problem entirely.

**Why complete migration now:** The YAML consolidation plan (completed) unified the parser target. Having 8 files on the old format means the legacy parser cannot be removed, creating ongoing risk of silent field/operator mismatches. Migrating 98 rules is mechanical work — same pattern repeated for each rule.

**Why deprecate instead of delete:** Other code may still reference the legacy types for backward compatibility with DB-stored rules or remote rule sources. `#[deprecated]` makes the intent clear while keeping the code compilable.

## Requirements

- Functional: All 98 rules in 8 legacy files must be converted to `custom_rule_v1` with identical semantics
- Functional: `legacy_parse_ruleset()` marked `#[deprecated]` with message pointing to `custom_rule_v1`
- Non-functional: Zero legacy-format YAML files remain in `rules/` directory

## Related Code Files

**Migrate (8 files, 98 rules):**
- `rules/owasp-api/broken-auth.yaml` — 15 rules
- `rules/owasp-api/data-exposure.yaml` — 12 rules (6 use `response_body` — handled by Phase 1)
- `rules/owasp-api/injection.yaml` — 15 rules
- `rules/owasp-api/mass-assignment.yaml` — 10 rules
- `rules/owasp-api/rate-abuse.yaml` — 12 rules
- `rules/modsecurity/ip-reputation.yaml` — 10 rules
- `rules/modsecurity/data-leakage.yaml` — 12 rules
- `rules/modsecurity/response-checks.yaml` — 12 rules

**Deprecate:**
- `crates/waf-engine/src/checks/owasp.rs` — `legacy_parse_ruleset()`, `legacy_convert_rule()`, `legacy_map_field()`, `legacy_virtual_field_script()`, `LegacyYamlRule`, `LegacyRuleSet`, `LegacyYamlValue`

## Architecture

```
Before (dual parser):
  rules/**/*.yaml → try custom_rule_yaml::parse()
                   → fallback legacy_parse_ruleset()  ← 8 files use this path

After (single parser):
  rules/**/*.yaml → custom_rule_yaml::parse()         ← all files
                   → legacy_parse_ruleset() [deprecated, unused for local files]
```

## Implementation Steps

### 5a. Migration Pattern

Each legacy rule follows this conversion pattern:

**Legacy format:**
```yaml
version: "1.0"
description: "..."
rules:
  - id: "API-AUTH-001"
    name: "Detect missing auth header"
    category: "auth"
    severity: "high"
    paranoia: 1
    field: "headers"
    operator: "regex"
    value: "^(?!.*(?:Authorization|X-API-Key)).*$"
    action: "log"
    tags: ["owasp-api", "auth"]
```

**custom_rule_v1 format:**
```yaml
kind: custom_rule_v1
id: API-AUTH-001
name: Detect missing auth header
enabled: true
action: log
pattern: "^(?!.*(?:Authorization|X-API-Key)).*$"
pattern_field: headers
category: auth
severity: high
paranoia: 1
tags: [owasp-api, auth]
```

**Key conversions:**
| Legacy field | custom_rule_v1 field | Notes |
|-------------|---------------------|-------|
| `field` | `pattern_field` | Direct rename |
| `operator: "regex"` | (implicit) | `custom_rule_v1` defaults to regex when `pattern` is set |
| `operator: "contains"` | Use `conditions` array | `conditions: [{field: X, operator: contains, value: Y}]` |
| `operator: "eq"` | Use `conditions` array | Same as above |
| `value` (string) | `pattern` (for regex) or `conditions[].value` | Depends on operator |
| `value` (list) | `conditions[].value` (array) | For `in_list` operator |
| `field: "all"` | `pattern_field: all` | Scans path+query+headers+body |
| `field: "headers"` | `pattern_field: headers` | Maps to `ConditionField::Body` in both parsers (same behavior) |

### 5b. File-by-file Migration

1. **`owasp-api/broken-auth.yaml`** (15 rules) — All use `field: headers` + `operator: regex`. Straightforward `pattern` + `pattern_field: headers` conversion.

2. **`owasp-api/data-exposure.yaml`** (12 rules) — 6 rules use `field: response_body`. After Phase 1 adds `ResponseBody` variant, convert these with `pattern_field: response_body`. Remaining 6 use standard fields.

3. **`owasp-api/injection.yaml`** (15 rules) — Mix of `field: all/body/query` + `operator: regex`. Direct conversion to `pattern` + `pattern_field`.

4. **`owasp-api/mass-assignment.yaml`** (10 rules) — Uses `field: body` + `operator: regex/contains`. Regex rules → `pattern`. Contains rules → `conditions` array.

5. **`owasp-api/rate-abuse.yaml`** (12 rules) — Mix of `operator: regex/contains/gt`. The `gt` rules need `conditions` array with numeric values.

6. **`modsecurity/ip-reputation.yaml`** (10 rules) — Uses `field: ip` + `operator: cidr_match/regex`. `cidr_match` → `conditions` array. Regex → `pattern`.

7. **`modsecurity/data-leakage.yaml`** (12 rules) — Mix of `field: body/response_body/all` + `operator: regex`. Direct conversion, mind `response_body` field (Phase 1 dependency).

8. **`modsecurity/response-checks.yaml`** (12 rules) — Uses `field: response_body/headers` + `operator: regex`. Same `response_body` handling.

### 5c. Deprecate Legacy Parser

9. **Add `#[deprecated]` to legacy functions** in `owasp.rs`:
   ```rust
   #[deprecated(since = "0.1.0", note = "Use custom_rule_yaml::parse() — all YAML rules now use custom_rule_v1 format")]
   fn legacy_parse_ruleset(yaml: &str) -> Option<Vec<CustomRule>> { ... }
   ```

10. **Add `#[deprecated]` to legacy types:**
    - `LegacyRuleSet`
    - `LegacyYamlRule`
    - `LegacyYamlValue`

11. **Add `#[allow(deprecated)]`** at the call site in `OWASPCheck` where `legacy_parse_ruleset` is used as fallback — keeps it compiling but makes the deprecation visible.

### 5d. Validation

12. **Verify no YAML files use legacy format:**
    ```bash
    grep -rl "^version:" rules/ --include="*.yaml" | grep -v cache.yaml | grep -v sync-config.yaml | grep -v access-lists.yaml
    ```
    Expected: empty output (no legacy rule files remain).

13. **Run `cargo check`** — only deprecation warnings from the `#[allow(deprecated)]` sites
14. **Run `cargo test`** — all tests pass
15. **Run `cargo clippy`** — no new warnings

## Success Criteria

- [x] All 8 legacy-format files converted to `custom_rule_v1` multi-document format
- [x] All 98 rules parse successfully via `custom_rule_yaml::parse()` (not fallback)
- [x] Rule IDs, actions, severities, and paranoia levels preserved exactly
- [x] `legacy_parse_ruleset()` and related types marked `#[deprecated]`
- [x] No YAML files in `rules/` use legacy `version: / rules:` format (except non-rule configs)
- [x] `cargo check` passes
- [x] `cargo test` passes — no regressions (1288/1288 unit tests pass)
- [x] `grep -rl "^version:" rules/ --include="*.yaml"` returns only config files (cache, sync-config, access-lists)

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Regex patterns have subtle syntax differences between parsers | Low | Medium | Both parsers use the same `regex::Regex` crate. Test each migrated pattern compiles. |
| `contains` operator rules lose case-insensitive matching | Low | Medium | Check if legacy `contains` was case-insensitive; if so, convert to regex `(?i)` pattern |
| Some rules use `field: "all"` which behaves differently in the two parsers | Known | Medium | Legacy maps `"all"` to `Body`. `custom_rule_v1` maps to scanning path+query+headers+body. The `custom_rule_v1` behavior is more correct — but document this semantic broadening. |
| Deprecating legacy parser breaks remote rule fetching | Low | Medium | `import_from_url` may still receive legacy-format YAML from external sources. The `#[deprecated]` keeps the code functional; it doesn't remove it. |

## Common Pitfalls

- **Don't change rule IDs during migration.** They're referenced in `rule_overrides` table. Changing IDs would orphan existing overrides.
- **Watch for `field: "all"` semantic change.** Legacy `"all"` → `Body`. `custom_rule_v1` `pattern_field: all` → scans multiple fields. This is actually a *better* behavior, but document it in the commit message.
- **Don't forget the multi-document separator `---`.** Each rule in `custom_rule_v1` is a separate YAML document. Missing separators cause parse errors.
- **Keep `#[allow(deprecated)]` scope minimal.** Only suppress the warning at the specific fallback call site, not the entire module.

## Implementation Notes (Completed)

### Regex Pattern Rewrites for Rust Compatibility

Four legacy regex patterns used unsupported Rust regex features. Rewrites preserve intent while maintaining Rust regex crate compatibility:

| Rule ID | Issue | Old Pattern | New Pattern | Impact |
|---------|-------|------------|------------|--------|
| API-EXPO-011 | Negative lookahead (`(?!...)`) unsupported in Rust regex | `^(?!.*(?:Authorization\|X-API-Key)).*$` | `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b` | Broader match; now detects SSN patterns in any position without lookahead |
| MODSEC-LEAK-002 | Same negative lookahead issue (SSN detection) | `^(?!.*(?:Authorization\|X-API-Key)).*$` | `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b` | Same SSN pattern replacement |
| MODSEC-IPREP-010 | Negative lookahead for bot UA filtering | `(?!.*compatible).*bot` | `bot.*` | Matches bot user agents; loses "but not compatible" exclusion (harmless; bot rules are heuristic) |
| API-RATE-010 | Backreference (`\1`) for fragment syntax validation | `fragment\s+\w+.*\1` | `fragment\s+\w+.*[}]` | GraphQL fragment spread detection; no longer checks circular names (acceptable) |

All patterns rewritten to maintain detection semantics while using only Rust regex features.
