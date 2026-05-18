# YAML Consolidation Phase 5: Cleanup and Deprecation

**Date**: 2026-05-18 13:35
**Severity**: Low
**Component**: waf-engine rules/formats, rules/manager
**Status**: Resolved

## What Happened

Phase 5 added deprecation warnings to legacy Registry-format parsers (`yaml.rs`, `json.rs`) and updated `import_from_url` to prefer `custom_rule_v1` format with graceful fallback to legacy parsers. No code was deleted — legacy parsers remain functional but now emit `tracing::warn!` on every call. A `custom_rule_to_registry()` conversion bridge was added so `custom_rule_v1` rules can populate the `RuleRegistry` used by the admin API.

## The Brutal Truth

**This phase was almost a no-op.** Phase 4 already did the heavy lifting — unifying OWASPCheck to use `CustomRulesEngine`, removing `is_routing_header` from `owasp.rs`, and migrating 490 YAML rules. Phase 5 just sprinkles deprecation warnings and reorders a fallback chain. The plan estimated 3h; actual was ~30min of meaningful changes.

**Double-warning trap caught in self-review.** Initial implementation put deprecation warnings in both `parse_rules()` (the dispatcher) AND `yaml::parse()` / `json::parse()` (the actual parsers). Every call through `parse_rules()` would log twice. Fixed by keeping warnings only in the leaf parsers — single responsibility, single warning.

**`format!("{:?}")` for action mapping was a code smell.** First version used `format!("{:?}", cr.action).to_lowercase()` to convert `RuleAction::Block` → `"block"`. That relies on Debug format stability — fragile. Replaced with explicit `match` on all four variants. Small thing, but exactly the kind of shortcut that breaks silently on enum additions.

## Technical Details

**Files modified:**
- `formats/yaml.rs` — `tracing::warn!` in `parse()`
- `formats/json.rs` — `tracing::warn!` in `parse()`
- `formats/mod.rs` — doc comment updated, no double-warn
- `manager.rs` — `import_from_url` tries `custom_rule_v1` first; added `try_custom_rule_v1_as_registry()` and `custom_rule_to_registry()` helpers

**Fallback chain in `import_from_url`:**
```
custom_rule_v1 → legacy yaml → legacy json
```

**What was NOT done (intentionally):**
- Step 7 (validation enhancement for custom_rule_v1 rules) — deferred, not in scope for deprecation
- Deleting yaml.rs/json.rs — remote sources may still serve Registry format; delete in next release
- validate_rules() update — existing validation still works through legacy parsers

## Key Decisions

| Decision | Rationale |
|----------|-----------|
| Warn in leaf parsers only, not dispatcher | Avoid double-logging on every parse_rules() call |
| Explicit match for RuleAction → string | Debug format is unstable across Rust editions |
| Bail on empty custom_rule_v1 result | Ensures fallback to legacy parsers when content has no `kind` discriminator |
| Map `cr.reference` → `Rule.description` | CustomRule has no `description` field; `reference` is closest semantic match |

## Verification

- 1277 unit tests pass
- 27 integration tests pass (8 format dispatch + 17 acceptance + 2 hot-reload)
- Zero compiler warnings
- `cargo fmt --all -- --check` clean
