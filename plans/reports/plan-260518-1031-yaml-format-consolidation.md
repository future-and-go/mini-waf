# Plan Report: YAML Rule Format Consolidation

**Date:** 2026-05-18
**Plan:** `plans/260518-1031-yaml-format-consolidation/`
**Source:** brainstorm-260516-2224 + predict-260516-2234

## Discovery

Codebase has **3 independent YAML rule parsing paths** (reports only identified 2):

1. `yaml.rs` → `RuleRegistry` (flat rules, `RuleManager::load_from_dir`)
2. `custom_rule_yaml.rs` → `CustomRulesEngine` (conditions/match_tree)
3. `owasp.rs::RuleSet` → `OWASPCheck` (field+operator+pattern, detect_sqli/xss)

Path 3 was missed in brainstorm. It has its own `CompiledRule`, `CompiledMatcher`, field matching with URL-decode, and routing-header exclusion. 351 rules across 30 files.

## Decisions

| Decision | Choice | Why |
|----------|--------|-----|
| Scope | Full consolidation (all 3 parsers) | True single source of truth |
| Field targeting | Reuse OWASPCheck's `field:` approach | Already proven, no new concepts |
| Special matchers | Expand CustomRulesEngine operators | Full unification into one engine |
| Migration | In-place overwrite | Cleaner git diff |
| Execution | Sequential (6 phases) | Simpler tracking |

## Plan Summary

6 phases, ~29h total effort, sequential execution:

1. **Extend CustomRule Struct** (4h) — Add pattern, field, category, severity, paranoia, tags, metadata, reference
2. **Pattern Evaluation Engine** (6h) — field matching, URL-decode bypass protection, operator shorthand
3. **Migration Script** (4h) — Convert 351 rules to custom_rule_v1
4. **OWASPCheck Unification** (8h) — Replace OWASPCheck pipeline with CustomRulesEngine
5. **Cleanup and Deprecation** (3h) — Deprecate yaml.rs/json.rs
6. **Integration Tests** (4h) — Loading, equivalence, paranoia, hot-reload tests

## Key Risks

- OWASPCheck regression (351 rules, special matchers) — mitigated by before/after equivalence tests
- `pm_from_file` path resolution — needs testing with actual `.data` files
- Performance (pattern matching all fields) — short-circuit order + field targeting
