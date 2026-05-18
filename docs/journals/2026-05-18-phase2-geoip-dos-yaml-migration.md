# Phase 2: Migrate Legacy GeoIP & DoS Rules to custom_rule_v1

**Date**: 2026-05-18 19:46
**Severity**: Medium
**Component**: rules/geoip, rules/modsecurity, waf-engine rule parser
**Status**: Resolved

## What Happened

Migrated `geoip/country-blocklist.yaml` (2 rules) and `modsecurity/dos-protection.yaml` (12 rules) from legacy nested format to `custom_rule_v1` multi-document format. Both files had silent failures in the legacy parser that caused rules to be dropped without warning.

**GeoIP bugs fixed:** `operator: "in"` unmapped by `legacy_convert_rule()` (rule dropped). `field: "geo_iso"/"geo_isp"` mapped to `Body` by `legacy_map_field()` (wrong field evaluated).

**DoS bugs fixed:** `value: "1024"` (string-quoted integer) rejected by `legacy_virtual_field_script()` which expected `LegacyYamlValue::Int` (rules dropped).

## Key Decisions

**Conditions vs pattern:** Rules needing exact field matching (`content_length gt`, `geo_iso in_list`) use `conditions:` array with typed `ConditionField` deserialization. Regex rules (`headers`, `method`, `body`) use `pattern:` + `pattern_field:` which routes through `pattern_matches_request()`. Content-type regex rules use `conditions:` because `pattern_field: content_type` falls through to "all" catch-all in `pattern_matches_request()`.

**Virtual fields use Rhai scripts:** `path_length` and `query_arg_count` have no `ConditionField` equivalent. Used `script:` field: `path.len() > 1024` and `query.split("&").len() > 255`.

**MODSEC-DOS-011 deviation:** Original regex `.{8192,}` exceeded the 1MB compiled DFA size limit enforced by the engine's `RegexBuilder`. Converted to Rhai script `cookie.len() >= 8192`. Required adding `cookie` variable to the Rhai scope in `eval_script()` (1 line addition).

## Unresolved Observations (from code review)

1. `parse_pattern_field_to_condition()` missing GeoIP fields — not triggered since migrated rules use `conditions:` array, but a footgun for future rule authors using operator+value shorthand.
2. MODSEC-DOS-012 (`regex: "^$"` on content_type) fires when header is absent (field_value returns None, unwrapped to ""). Preserves legacy semantics; low blast radius (log + paranoia 2).
3. MODSEC-DOS-007 uses unanchored regex for content-type matching — matches substrings. Preserves legacy semantics.

## Impact

Legacy file count drops from 11 to 9. All 14 rules now parse and load correctly through the `custom_rule_v1` parser. 1288 unit tests pass, 2 new integration tests validate parsing of all migrated rules.
