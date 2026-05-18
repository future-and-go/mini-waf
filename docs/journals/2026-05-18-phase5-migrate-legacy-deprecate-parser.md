# Phase 5: Migrate All Legacy Files & Deprecate Parser

**Date:** 2026-05-18
**Phase:** 5 of rules-yaml-db-schema-alignment
**Status:** Completed

## Summary

Migrated 8 legacy-format YAML rule files (98 rules) to `custom_rule_v1` multi-document format. Deprecated all legacy parser functions/types in `owasp.rs`. Eliminated the dual-parser problem — all local rule files now use a single parser path.

## Changes

### YAML Migration (8 files, 98 rules)
- `rules/owasp-api/broken-auth.yaml` — 15 rules
- `rules/owasp-api/data-exposure.yaml` — 12 rules (6 use response_body)
- `rules/owasp-api/injection.yaml` — 15 rules
- `rules/owasp-api/mass-assignment.yaml` — 10 rules
- `rules/owasp-api/rate-abuse.yaml` — 12 rules
- `rules/modsecurity/ip-reputation.yaml` — 10 rules
- `rules/modsecurity/data-leakage.yaml` — 12 rules
- `rules/modsecurity/response-checks.yaml` — 12 rules

### Legacy Parser Deprecation
7 items deprecated in `crates/waf-engine/src/checks/owasp.rs`:
- Types: `LegacyRuleSet`, `LegacyYamlRule`, `LegacyYamlValue`
- Functions: `legacy_parse_ruleset`, `legacy_convert_rule`, `legacy_rule_shell`, `legacy_virtual_field_script`, `legacy_map_field`
- `#[allow(deprecated)]` scoped to 2 fallback call sites + internal cross-refs

### Regex Pattern Fixes
4 patterns rewritten for Rust `regex` crate compatibility (negative lookaheads and backreferences unsupported):

| Rule | Issue | Fix |
|------|-------|-----|
| API-EXPO-011 | `(?!...)` lookahead in SSN pattern | Broader `\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b` |
| MODSEC-LEAK-002 | Same SSN lookahead | Same fix |
| MODSEC-IPREP-010 | `(?!...)` in fake bot UA detection | Removed exclusion clause |
| API-RATE-010 | `\1` backreference for circular fragment | Match fragment spread syntax without name check |

## Key Decision

**Why rewrite instead of fancy-regex?** Adding a second regex engine increases binary size and eval latency for 4 rules. The lookaheads were niceties (SSN false-positive reduction, bot UA exclusion) not correctness requirements. Simpler patterns with slightly broader matching are acceptable for a WAF's detection heuristics.

## Validation

- `cargo check` — 0 warnings
- `cargo test --lib` — 1288/1288 passed
- `grep -rl "^version:" rules/ --include="*.yaml"` — only config files remain

## Semantic Note

`data-leakage.yaml` and `response-checks.yaml` rules use `pattern_field: body` despite targeting response inspection. This preserves legacy behavior (`field: "body"` mapped to `ConditionField::Body` in both parsers). Changing to `response_body` would alter runtime behavior — deferred to a separate evaluation.
