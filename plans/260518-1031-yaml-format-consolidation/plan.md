---
title: "YAML Rule Format Consolidation — Unified custom_rule_v1"
description: "Consolidate all three YAML rule parsers (yaml.rs, custom_rule_yaml.rs, owasp.rs RuleSet) into a single custom_rule_v1 format with pattern/field evaluation"
status: pending
priority: P1
branch: "main"
tags: [rule-engine, yaml, consolidation, refactor]
blockedBy: []
blocks: []
created: "2026-05-18T03:36:18.092Z"
createdBy: "ck:plan"
source: skill
---

# YAML Rule Format Consolidation — Unified custom_rule_v1

## Overview

Three incompatible YAML rule parsing paths exist in waf-engine:

1. **`yaml.rs`** → `RuleRegistry` (flat rules, `RuleManager::load_from_dir`)
2. **`custom_rule_yaml.rs`** → `CustomRulesEngine` (conditions/match_tree, `custom_file_loader`)
3. **`owasp.rs::RuleSet`** → `OWASPCheck` (field+operator+pattern, recursive `walk_directory`)

This creates: silent data loss (fields ignored), duplicate compilation logic, three struct hierarchies for the same concept, and 351 rules using a format with no `kind` discriminator.

**Target:** Consolidate all into `custom_rule_v1` format with pattern+field evaluation reusing OWASPCheck's proven `field: all/path/query/body` approach.

## Source Reports

- [Brainstorm](../reports/brainstorm-260516-2224-yaml-format-consolidation.md) — Technical solution design
- [Prediction](../reports/predict-260516-2234-yaml-format-consolidation.md) — Risk analysis and recommendations

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Target format | `custom_rule_v1` | Version discriminator, nested boolean logic, forward-compatible |
| Field targeting | Reuse `field:` from OWASPCheck | Already proven, no new concepts needed |
| Migration | Big-bang script (Rust) | 351 rules, reuse existing serde types |
| Parser scope | All 3 parsers | True consolidation, single source of truth |

## Phases

| Phase | Name | Status | Priority | Effort | Depends |
|-------|------|--------|----------|--------|---------|
| 1 | [Extend CustomRule Struct](./phase-01-extend-customrule-struct.md) | Done | P1 | 4h | — |
| 2 | [Pattern Evaluation Engine](./phase-02-pattern-evaluation-engine.md) | Done | P1 | 6h | Phase 1 |
| 3 | [Migration Script](./phase-03-migration-script.md) | Done | P1 | 4h | Phase 1 |
| 4 | [OWASPCheck Unification](./phase-04-owaspcheck-unification.md) | Done | P1 | 8h | Phases 2, 3 |
| 5 | [Cleanup and Deprecation](./phase-05-cleanup-and-deprecation.md) | Pending | P2 | 3h | Phase 4 |
| 6 | [Integration Tests and Validation](./phase-06-integration-tests-and-validation.md) | Pending | P1 | 4h | Phase 4 |

## Architecture Change

```
BEFORE (3 paths):
  rules/advanced/*.yaml  ──→ yaml.rs::parse()     ──→ RuleRegistry
  rules/custom/*.yaml    ──→ custom_rule_yaml.rs   ──→ CustomRulesEngine
  rules/**/*.yaml        ──→ owasp.rs::RuleSet     ──→ OWASPCheck

AFTER (1 path):
  rules/**/*.yaml        ──→ custom_rule_yaml.rs   ──→ CustomRulesEngine
                              (with pattern+field)      (unified eval)
```

## Dependencies

- No cross-plan dependencies detected
