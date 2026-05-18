# Code Review: Rules YAML Format & DB Mapping Compatibility

**Date:** 2026-05-18  
**Scope:** 57 YAML files in `rules/`, migration `0007_rule_management.sql`, 8 Rust parser files  
**Focus:** Format consistency, DB schema mapping, adaptability

---

## 1. Format Catalog

| Format | Schema | Directories | Count |
|--------|--------|-------------|-------|
| **custom_rule_v1** | Multi-doc YAML with `kind: custom_rule_v1`, fields: `id/name/pattern/pattern_field/action/category/severity/paranoia/tags/metadata` | advanced/, bot-detection/, cve-patches/, owasp-crs/, custom/ (FR-003 samples) | **43** |
| **legacy-nested** | Single doc, `version/description/rules: [{id,name,category,severity,field,operator,value,action,tags}]` | owasp-api/, modsecurity/, geoip/, custom/example.yaml | **11** |
| **config/meta** | System config — not rules | access-lists.yaml, sync-config.yaml, cache.yaml | **3** |
| **threat-intel** | Unique: `asns: [int]`, `cidrs: [str]` | threat-intel/ | **1** |

---

## 2. Compatibility Matrix

### `rule_overrides` table

| DB Column | Type | YAML Source | Status |
|-----------|------|-------------|--------|
| `rule_id` | VARCHAR(100) | `id` field | OK — max 30 chars observed |
| `host_id` | UUID FK | Runtime only | OK |
| `enabled` | BOOLEAN | `enabled` field (defaults true) | OK |
| `action_override` | VARCHAR(20) | `action` field | OK — max 9 chars (`challenge`) |
| `note` | TEXT | N/A | OK — runtime only |

**Data loss on import:** `paranoia`, `tags`, `metadata`, `reference`, `risk_delta`, `category`, `severity` have no DB columns — lost if rules stored only in `rule_overrides`.

### `rule_sources` table

| DB Column | Type | YAML Source | Status |
|-----------|------|-------------|--------|
| `name` | VARCHAR(100) | sync-config key names | OK |
| `source_type` | VARCHAR(20) | `local_file\|local_dir\|remote_url\|builtin` | **ISSUE:** `builtin` not in API `ALLOWED_SOURCE_TYPES` |
| `url` | VARCHAR(1000) | sync-config `repo` | OK |
| `path` | VARCHAR(500) | directory paths | OK |
| `format` | VARCHAR(20) | yaml/json/modsec | OK |
| `last_hash` | VARCHAR(64) | Runtime computed | OK |

### `bot_patterns` table

| DB Column | Type | Bot YAML Field | Status |
|-----------|------|----------------|--------|
| `pattern` | VARCHAR(500) | `pattern` | **ISSUE:** Some patterns >500 chars |
| `pattern_type` | VARCHAR(20) | `pattern_field` | **ISSUE:** YAML uses `user_agent/headers/body/path`, DB expects `ua\|ip\|behavior` |
| `action` | VARCHAR(20) | `action` | **PARTIAL:** `challenge` (Rust enum) ≠ `captcha` (DB constraint) |
| `description` | TEXT | `name` | OK |
| `enabled` | BOOLEAN | `enabled` | OK |

---

## 3. Issues Found

### CRITICAL

**C1. `response_body` silently misrouted — 53 rules affected**
- Files: `owasp-crs/web-shells.yaml` (27), `data-leakage-sql.yaml` (16), `data-leakage.yaml` (3), `data-leakage-java.yaml` (1), `owasp-api/data-exposure.yaml` (6)
- `parse_pattern_field_to_condition()` at `custom_rule_yaml.rs:220` maps unknown fields (including `response_body`) to `ConditionField::Body` (request body)
- **Impact:** 53 rules meant to detect data leakage in HTTP *responses* are evaluating against *request* bodies. They will never trigger on intended content, creating false sense of protection.
- **Fix:** Add `ResponseBody` variant to `ConditionField`, or log WARNING on `response_body` instead of silent fallback.

**C2. GeoIP rules completely non-functional**
- File: `geoip/country-blocklist.yaml` (legacy format)
- Rule `GEO-COUNTRY-001` uses `operator: "in"` — legacy parser `owasp.rs:382` hits catch-all `op =>` branch, logs debug, returns `None` → rule silently dropped
- Rule `GEO-COUNTRY-001/002` use `field: "geo_iso"/"geo_isp"` — `legacy_map_field()` has no mapping → falls to `ConditionField::Body`
- **Impact:** Country blocklist provides zero protection. Both operator and field mapping fail silently.
- **Fix:** Migrate to `custom_rule_v1` format (which handles `"in"` at `custom_rule_yaml.rs:235`) or add `"in"` handling to legacy parser.

**C3. `modsecurity/dos-protection.yaml` value type mismatch**
- Rules with `value: "1024"` (string) + `operator: "gt"` — `LegacyYamlValue` serde picks `Str` variant, but `legacy_virtual_field_script` expects `Int` → returns `None` → rule dropped
- **Fix:** Change to `value: 1024` (unquoted integer) or migrate to `custom_rule_v1`.

### IMPORTANT

**I1. `bot_patterns.pattern` VARCHAR(500) too short**
- Some regex patterns in `bot-detection/crawlers.yaml` and `credential-stuffing.yaml` exceed 500 chars
- INSERT would fail with truncation error
- **Fix:** ALTER to `TEXT` or `VARCHAR(2000)`

**I2. `bot_patterns.pattern_type` enum mismatch**
- DB: `ua | ip | behavior`
- YAML: `user_agent`, `headers`, `body`, `path`
- No mapping layer exists. Bot rules targeting `headers` or `body` have no DB equivalent.
- **Fix:** Expand DB constraint or add mapping layer in import code

**I3. `builtin` source type rejected by API**
- `rule_sources_api.rs` validates `ALLOWED_SOURCE_TYPES = ["local_file", "local_dir", "remote_url"]`
- `RuleSource` Rust enum has `Builtin` variant
- API creation of builtin sources fails, only direct SQL works

**I4. Two parallel rule pipelines parse same files differently**
- `RuleManager.load_from_dir` uses deprecated `yaml::parse` (expects flat arrays)
- `OWASPCheck` uses `custom_rule_yaml::parse` first, falls back to legacy
- Same YAML files parsed by different parsers in different contexts → inconsistent behavior

**I5. `action: "challenge"` vs `bot_patterns.action` CHECK constraint**
- Rust `RuleAction` allows `Challenge`, but DB constraint only permits `block|log|captcha|allow`
- No bot rules currently use `challenge`, but type system permits it

### MINOR

**M1.** `custom/example.yaml` uses legacy format; `custom_file_loader` only parses `custom_rule_v1` → example silently ignored  
**M2.** `sync-config.yaml` has Git fields (`repo`, `branch`, `tag`) with no `rule_sources` columns  
**M3.** Inconsistent `severity` — one rule uses `error` (`CRS-952110`), rest use `critical/high/medium/low`  
**M4.** `threat-intel/hyperscaler-asn-seed.yaml` has unique schema (no rule IDs) — separate loader, OK  
**M5.** `cache.yaml` and `access-lists.yaml` are not rule files — separate parsers, OK

---

## 4. Adaptability Score: 6/10

**Strengths:**
- `custom_rule_v1` format is well-designed with serde defaults, forward-compatible
- Rule IDs short (max 30 chars vs 100 limit), zero duplicates across 616 rules
- Action values fit VARCHAR(20)
- `metadata` HashMap provides extensibility without schema changes
- New rule categories addable as YAML files without code changes

**Weaknesses:**
- Two active formats with different field names and parsing paths
- `response_body` field unsupported, creating silent failures (53 rules)
- `bot_patterns` table schema incompatible with YAML bot-detection structure
- Legacy format files cannot be auto-migrated due to incompatible operator/field mappings
- Multiple YAML fields (paranoia, tags, metadata, etc.) have no DB columns

---

## 5. Recommended Actions (Priority Order)

1. **[CRITICAL]** Fix `response_body` — add `ResponseBody` variant to `ConditionField` or at minimum log WARNING instead of silent fallback
2. **[CRITICAL]** Migrate `geoip/country-blocklist.yaml` to `custom_rule_v1` format
3. **[CRITICAL]** Fix `modsecurity/dos-protection.yaml` — unquote integer values or migrate format
4. **[IMPORTANT]** Widen `bot_patterns.pattern` to `TEXT`
5. **[IMPORTANT]** Add `pattern_field → pattern_type` mapping layer for bot import
6. **[MEDIUM]** Migrate remaining 11 legacy files to `custom_rule_v1`
7. **[MEDIUM]** Update `custom/example.yaml` to `custom_rule_v1` format

---

## Unresolved Questions

1. Are the 53 `response_body` rules intended for response-time evaluation via gateway `response_body_filter`, or request-time? If response-time, they belong in a different evaluation pipeline.
2. Is `geoip/country-blocklist.yaml` expected to be functional today or a template? Currently completely broken.
3. Should `bot_patterns` table coexist with bot-detection YAML rules, or serve as separate runtime overlay? Schemas are incompatible.
4. Should `RuleManager.load_from_dir()` also try `custom_rule_v1` parsing, or only the legacy path?
