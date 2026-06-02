# Phase 4: Sync API Validation & Parser Cleanup

**Date:** 2026-05-18
**Scope:** P2 impedance mismatches and developer experience fixes
**Commit:** 9798af3

## Changes

1. **Legacy field warning upgrade** (`owasp.rs:465`) — `debug!` → `warn!` for unknown legacy fields in `legacy_map_field()`. Now consistent with `parse_pattern_field_to_condition()` in `custom_rule_yaml.rs` which already used `warn!`.

2. **Builtin source type clarification** (`rule_sources_api.rs:127`) — Added comment explaining why `"builtin"` is intentionally excluded from `ALLOWED_SOURCE_TYPES`. Builtin sources are config-managed via TOML flags, not DB-stored.

3. **Example YAML rewrite** (`rules/custom/example.yaml`) — Converted 7 rules from legacy format (silently ignored by `custom_file_loader`) to multi-document `custom_rule_v1` format. All rules set `enabled: false`.

4. **Severity value fix** (`data-leakage-java.yaml`, `data-leakage.yaml`) — Fixed 5 occurrences of `severity: error` → `severity: critical`. "error" was not a valid severity in the standard set (critical/high/medium/low).

## Key Decision

**Reverted builtin API addition.** The plan originally called for adding `"builtin"` to `ALLOWED_SOURCE_TYPES`. Code reviewer identified design tension: module docs (lines 18-20) explicitly state builtin sources are NOT stored in the DB table. Adding `"builtin"` to the POST validation would allow creating dead rows the engine never consumes. Correct fix: keep exclusion, add clarifying comment.

## Plan Corrections

- Plan referenced `response-sql-errors.yaml` for CRS-952110 severity fix — actual file was `data-leakage-java.yaml`
- `parse_pattern_field_to_condition()` warning was already done in Phase 3 — no duplicate work needed

## Validation

- `cargo check` / `cargo clippy`: clean
- 1,757 unit tests: all pass
- Integration tests (Docker-dependent): pre-existing failures, unrelated
