---
phase: 2
title: "Migrate Legacy GeoIP & DoS Rules"
status: done
priority: P1
effort: "2h"
dependencies: []
---

# Phase 2: Migrate Legacy GeoIP & DoS Rules

## Overview

Two critical silent failures in legacy-format YAML files:

1. **GeoIP** (`geoip/country-blocklist.yaml`): Uses `operator: "in"` which the legacy parser's `legacy_convert_rule()` doesn't handle — rule silently dropped. Also uses `field: "geo_iso"/"geo_isp"` which `legacy_map_field()` maps to `Body` (wrong).
2. **DoS** (`modsecurity/dos-protection.yaml`): Rules with `value: "1024"` (string-quoted integer) + `operator: "gt"` — `legacy_virtual_field_script()` expects `LegacyYamlValue::Int`, gets `Str`, returns `None` — rules silently dropped.

**Why migration instead of fixing the legacy parser:** The YAML consolidation plan (completed) established `custom_rule_v1` as the single target format. Fixing the legacy parser would add code to a deprecated path. Migrating these 2 files to `custom_rule_v1` eliminates both bugs and reduces the legacy file count from 11 to 9.

**Alternative considered:** Fix string-to-int coercion in `LegacyYamlValue` deserialization. Rejected — this adds complexity to a deprecated parser, and the `"in"` operator still needs separate handling. Migration is cleaner.

## Requirements

- Functional: `geoip/country-blocklist.yaml` rules must evaluate correctly (country blocking works)
- Functional: `modsecurity/dos-protection.yaml` rules with `gt` operator must evaluate against numeric thresholds
- Functional: All existing rules in both files must be preserved with identical semantics

## Related Code Files

- Modify: `rules/geoip/country-blocklist.yaml` — rewrite from legacy to `custom_rule_v1` format
- Modify: `rules/modsecurity/dos-protection.yaml` — rewrite from legacy to `custom_rule_v1` format
- Read: `rules/advanced/ssrf.yaml` — reference for `custom_rule_v1` format
- Read: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` — verify `in_list` operator support (line 235)
- Read: `crates/waf-engine/src/rules/engine.rs` — verify `GeoIso`/`GeoIsp` variants exist (lines 47-53)

## Implementation Steps

### 2a. Migrate `geoip/country-blocklist.yaml`

1. **Convert `GEO-COUNTRY-001` to `custom_rule_v1` with conditions:**
   - `kind: custom_rule_v1` (top-level discriminator)
   - `pattern_field: geo_iso` → maps to `ConditionField::GeoIso` via `parse_pattern_field_to_condition()`
   - `operator: "in"` → maps to `Operator::InList` via `parse_operator_str()` (confirmed at `custom_rule_yaml.rs:235`)
   - Use `conditions` array with `field: geo_iso`, `operator: in_list`, `value: ["KP", "IR", "SY"]`

   **Before (broken):**
   ```yaml
   version: "1.0"
   rules:
     - id: "GEO-COUNTRY-001"
       field: "geo_iso"
       operator: "in"
       value: ["KP", "IR", "SY"]
       action: "block"
   ```

   **After (working):**
   ```yaml
   kind: custom_rule_v1
   id: GEO-COUNTRY-001
   name: Block requests from high-risk countries (example)
   enabled: true
   action: block
   conditions:
     - field: geo_iso
       operator: in_list
       value: ["KP", "IR", "SY"]
   category: geo
   severity: high
   paranoia: 1
   tags: [geoip, country-block]
   ```

2. **Convert `GEO-COUNTRY-002` similarly** — use `field: geo_isp`, `operator: contains`, `value: "Tor"`

3. **Use multi-document YAML** (separated by `---`) for both rules in one file

### 2b. Migrate `modsecurity/dos-protection.yaml`

4. **Convert all 12 rules** from legacy nested format to `custom_rule_v1` multi-document format

5. **Key conversions for each rule type:**
   - Rules with `field: content_length` + `operator: gt` + `value: "10485760"`:
     - Use `conditions: [{field: content_length, operator: gt, value: 10485760}]`
     - Note: `custom_rule_v1` parser uses `ConditionValue` which handles both string and integer values correctly
   - Rules with `field: path_length` / `field: query_arg_count` (virtual fields):
     - These require Rhai script in legacy format. In `custom_rule_v1`, use `script:` field directly
     - Example: `script: "path.len() > 1024"` for MODSEC-DOS-002
   - Rules with `field: all` + `operator: regex`:
     - Use `pattern_field: all` which `custom_rule_v1` handles natively (scans path+query+headers+body)
   - Standard `field: body/method/cookies/content_type` rules: direct mapping to `pattern_field` or `conditions`

6. **Preserve rule IDs, tags, severity, paranoia** — these must be identical to the legacy values

### 2c. Validation

7. **Run `cargo check`** — verify YAML files parse correctly
8. **Grep for the rule IDs** in test output to confirm they load:
   ```bash
   RUST_LOG=debug cargo test -- --nocapture 2>&1 | grep -E "GEO-COUNTRY|MODSEC-DOS"
   ```

## Success Criteria

- [ ] `geoip/country-blocklist.yaml` uses `kind: custom_rule_v1` format
- [ ] `GEO-COUNTRY-001` rule with `in_list` operator parses and loads successfully
- [ ] `GEO-COUNTRY-002` rule with `contains` operator on `geo_isp` field parses correctly
- [ ] `modsecurity/dos-protection.yaml` uses `kind: custom_rule_v1` format
- [ ] All 12 MODSEC-DOS rules parse without warnings/errors
- [ ] Rules with numeric thresholds (`gt`, `lt`) work correctly (not silently dropped)
- [ ] `cargo check` passes
- [ ] Existing tests pass — no regressions

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Rhai script syntax differs between legacy and `custom_rule_v1` | Low | Medium | Test `path.len() > 1024` script in unit test before committing |
| `in_list` operator handling differs from legacy `"in"` | Low | Low | Verified: `parse_operator_str` maps both `"in"` and `"in_list"` to `Operator::InList` |
| Virtual fields (path_length, query_arg_count) have no ConditionField equivalent | Known | Medium | Use `script:` field in `custom_rule_v1` — this is the documented approach |

## Common Pitfalls

- **Don't forget multi-document separator.** `custom_rule_v1` files use `---` between rules. Missing separator = parse error or rules merged.
- **Don't quote integer values.** `value: "1024"` in YAML is a string. `value: 1024` is an integer. The `custom_rule_v1` `ConditionValue` handles both, but unquoted integers are clearer and less error-prone.
- **Don't use `pattern_field` for virtual fields.** `path_length` and `query_arg_count` are computed values that don't exist in `ConditionField`. Use the `script:` field with Rhai expressions instead.
