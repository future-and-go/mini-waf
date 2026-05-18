---
title: "Rules YAML & DB Schema Alignment"
description: "Fix critical silent failures in rule parsing (response_body, geoip, DoS) and align bot_patterns DB schema with YAML rule format"
status: in-progress
priority: P1
branch: "main"
tags: [rule-engine, yaml, database, schema, bugfix]
blockedBy: []
blocks: []
created: "2026-05-18T09:39:52.188Z"
createdBy: "ck:plan"
source: skill
---

# Rules YAML & DB Schema Alignment

## Overview

Code review of 57 YAML rule files against `0007_rule_management.sql` found 3 critical silent failures and 5 important schema mismatches. 53 data-leakage rules evaluate against request body instead of response body. GeoIP country-blocklist rules are silently dropped (broken operator + field mapping). DoS threshold rules with string-quoted integers are silently dropped.

**Source:** [Code Review Report](../reports/code-review-260518-1614-rules-yaml-db-mapping.md)

## Phases

| Phase | Name | Status | Priority | Effort | Depends |
|-------|------|--------|----------|--------|---------|
| 1 | [Fix response_body Field Mapping](./phase-01-fix-response-body-field-mapping.md) | **Done** | P1 | 3h | — |
| 2 | [Migrate Legacy GeoIP & DoS Rules](./phase-02-migrate-legacy-geoip-dos-rules.md) | Pending | P1 | 2h | — |
| 3 | [Align bot_patterns DB Schema](./phase-03-align-bot-patterns-db-schema.md) | Pending | P1 | 2h | — |
| 4 | [Sync API Validation & Parser Cleanup](./phase-04-sync-api-validation-parser-cleanup.md) | Pending | P2 | 3h | 1, 2, 3 |
| 5 | [Migrate All Legacy Files & Deprecate Parser](./phase-05-migrate-all-legacy-deprecate-parser.md) | Pending | P2 | 4h | 2, 4 |

## Architecture Context

```
YAML Rule Loading (current state):
  custom_rule_v1 files (43) ──→ custom_rule_yaml.rs::parse()
     └─ parse_pattern_field_to_condition() ← BUG: response_body → Body fallback

  legacy-nested files (11)  ──→ owasp.rs::legacy_parse_ruleset()
     ├─ legacy_virtual_field_script()     ← BUG: string values → None
     ├─ legacy_convert_rule()             ← BUG: "in" operator → None
     └─ legacy_map_field()                ← BUG: geo_iso/geo_isp → Body

DB schema (0007_rule_management.sql):
  rule_sources   ── OK except: "builtin" not in API ALLOWED_SOURCE_TYPES
  rule_overrides ── OK for basic fields; loses paranoia/tags/metadata
  bot_patterns   ── Mismatched: pattern VARCHAR(500), pattern_type ua|ip|behavior
```

## Validation Decisions

| Question | Decision | Impact |
|----------|----------|--------|
| response_body rules: wire into pipeline or log-only? | **Wire into response pipeline** | Phase 1 does full integration with `response_body_filter()` |
| GeoIP file: production or template? | **Template/example** | Phase 2 migrates for correctness, not as production incident |
| Remaining 9 legacy files: scope? | **Migrate all + deprecate parser** | Added Phase 5 to migrate 8 remaining files (98 rules) and deprecate `legacy_parse_ruleset()` |

## Dependencies

- Builds on completed [YAML Format Consolidation](../260518-1031-yaml-format-consolidation/) plan
- Existing `response_body_content_scanner` gateway filter (FR-033) already handles response scanning — Phase 1 leverages this
