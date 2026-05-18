---
phase: 4
title: "Sync API Validation & Parser Cleanup"
status: done
priority: P2
effort: "3h"
dependencies: [1, 2, 3]
---

# Phase 4: Sync API Validation & Parser Cleanup

## Overview

After fixing the critical issues (Phases 1-3), this phase addresses the remaining important/minor issues from the code review to prevent future regressions:

1. **`builtin` source type rejected by API** — `ALLOWED_SOURCE_TYPES` in `rule_sources_api.rs:127` only accepts `local_file | local_dir | remote_url`, but the Rust `RuleSource` enum has a `Builtin` variant.
2. **Silent catch-all in `parse_pattern_field_to_condition()`** — `_ => ConditionField::Body` hides unknown field names. Should warn instead.
3. **`custom/example.yaml` uses legacy format** — `custom_file_loader` only parses `custom_rule_v1`, so the example is silently ignored and misleads users who copy it.
4. **Inconsistent severity value** — `CRS-952110` uses `severity: error` instead of the standard `critical/high/medium/low`.

**Why this is P2:** None of these cause silent rule failures (unlike Phases 1-3). They're impedance mismatches and developer experience issues. But left unfixed, they become sources of confusion and future bugs.

## Requirements

- Functional: `builtin` source type either accepted by API or explicitly documented as config-only
- Functional: Unknown `pattern_field` values produce a warning log, not silent fallback
- Functional: `custom/example.yaml` parseable by `custom_file_loader`
- Non-functional: No new warnings from `cargo clippy`

## Related Code Files

- Modify: `crates/waf-api/src/rule_sources_api.rs` — line 127, expand `ALLOWED_SOURCE_TYPES`
- Modify: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` — line 208, add warning for unknown fields
- Modify: `crates/waf-engine/src/checks/owasp.rs` — line 451, add warning for unknown fields in `legacy_map_field()`
- Modify: `rules/custom/example.yaml` — rewrite to `custom_rule_v1` format
- Modify: `rules/owasp-crs/response-sql-errors.yaml` — fix `CRS-952110` severity from `error` to `critical`

## Implementation Steps

### 4a. Fix API Source Type Validation

1. **Add `"builtin"` to `ALLOWED_SOURCE_TYPES`** in `rule_sources_api.rs:127`:

   **Before:**
   ```rust
   const ALLOWED_SOURCE_TYPES: &[&str] = &["local_file", "local_dir", "remote_url"];
   ```

   **After:**
   ```rust
   const ALLOWED_SOURCE_TYPES: &[&str] = &["local_file", "local_dir", "remote_url", "builtin"];
   ```

   **Why:** The `RuleSource` Rust enum already has `Builtin` with `source_type() => "builtin"`. The API should accept what the domain model defines. If `builtin` is intentionally restricted from API creation, add a comment explaining why — but currently the mismatch looks accidental.

### 4b. Replace Silent Catch-All with Warning

2. **Update `parse_pattern_field_to_condition()`** in `custom_rule_yaml.rs:208`:

   **Before:**
   ```rust
   // "all", "body", and unknown → Body
   _ => ConditionField::Body,
   ```

   **After:**
   ```rust
   "all" | "body" => ConditionField::Body,
   other => {
       tracing::warn!(field = other, "Unknown pattern_field, falling back to Body");
       ConditionField::Body
   }
   ```

   **Why:** This preserves the fallback behavior (nothing breaks) but makes unknown fields visible in logs. If someone adds a new `pattern_field` value to a YAML rule and forgets to update the parser, they'll see the warning instead of wondering why their rule doesn't work.

3. **Apply same pattern to `legacy_map_field()`** in `owasp.rs:451`:

   ```rust
   "all" | "body" | "headers" => ConditionField::Body,
   other => {
       tracing::warn!(field = other, "Unknown legacy field, falling back to Body");
       ConditionField::Body
   }
   ```

### 4c. Fix Example and Severity

4. **Rewrite `rules/custom/example.yaml`** from legacy format to `custom_rule_v1`:

   **Before (legacy, silently ignored):**
   ```yaml
   version: "1.0"
   rules:
     - id: "CUSTOM-EXAMPLE-001"
       name: "Example custom rule"
       ...
   ```

   **After (parseable by custom_file_loader):**
   ```yaml
   kind: custom_rule_v1
   id: CUSTOM-EXAMPLE-001
   name: Example custom rule — blocks requests containing test pattern
   enabled: false
   action: log
   pattern: "example-blocked-pattern"
   pattern_field: path
   category: custom
   severity: low
   paranoia: 1
   tags: [example, custom]
   metadata:
     note: "Rename and customize this file to create your own rules"
   ```

   **Note:** Keep `enabled: false` so the example doesn't accidentally block traffic.

5. **Fix severity on `CRS-952110`:**
   - In `rules/owasp-crs/response-sql-errors.yaml`, find rule with `severity: error`
   - Change to `severity: critical` (SQL error leakage is a critical data exposure)

### 4d. Validation

6. **Run `cargo check`** — zero warnings
7. **Run `cargo clippy`** — zero new warnings
8. **Run `cargo test`** — all pass
9. **Verify example YAML loads:**
   ```bash
   RUST_LOG=debug cargo test custom_file -- --nocapture 2>&1 | grep -i "example"
   ```

## Success Criteria

- [x] `ALLOWED_SOURCE_TYPES` — `"builtin"` intentionally excluded (config-managed, not API-created); added clarifying comment
- [x] Unknown `pattern_field` values produce `tracing::warn!` (not silent) — already done in Phase 3
- [x] Unknown legacy `field` values produce `tracing::warn!` (not silent) — upgraded `debug!` → `warn!`
- [x] `custom/example.yaml` uses `kind: custom_rule_v1` format — 7 rules converted, all `enabled: false`
- [x] `CRS-952110` has `severity: critical` instead of `error` — also fixed 4 more in `data-leakage.yaml`
- [x] `cargo check` passes
- [x] `cargo clippy` passes with zero new warnings
- [x] `cargo test` passes — 1,757 unit tests pass; integration tests require Docker (pre-existing)

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Warning log spam from legitimate `"all"` field usage | None | None | `"all"` is explicitly matched before the warning branch |
| Adding `"builtin"` to API allows unintended source creation | Low | Low | Builtin sources are typically read-only config; API creation is harmless |
| Changing example.yaml format breaks user documentation/tutorials | Low | Low | Example was silently ignored anyway; new format is actually functional |

## Common Pitfalls

- **Don't add `tracing::warn!` without the explicit `"all"` arm.** Many rules legitimately use `pattern_field: all`. If `"all"` falls into the warning branch, you'll get log noise on every request. Always match known-valid values explicitly before the catch-all.
- **Don't delete the catch-all fallback entirely.** Returning an error for unknown fields would break forward compatibility — a newer YAML file with a new field type would fail to load on an older binary. Warning + fallback is the correct pattern.
- **Keep `enabled: false` on example.yaml.** Users who don't customize the example file should not have it accidentally blocking traffic.
