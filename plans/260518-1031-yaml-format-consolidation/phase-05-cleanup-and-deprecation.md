---
phase: 5
title: "Cleanup and Deprecation"
status: done
priority: P2
effort: "3h"
dependencies: [4]
---

# Phase 5: Cleanup and Deprecation

## Overview

Remove the now-redundant Registry parser (`yaml.rs`, `json.rs`), update `formats/mod.rs` exports, add deprecation logging to any remaining entry points, and extract shared utilities (like `is_routing_header`) to avoid duplication.

## Requirements

- Functional: `yaml.rs` and `json.rs` parsers removed or deprecated with warning log
- Functional: `RuleManager` updated to use `custom_rule_yaml::parse` for file loading
- Functional: No dead code warnings
- Non-functional: `formats/mod.rs` exports cleaned up

## Related Code Files

- Modify: `crates/waf-engine/src/rules/formats/mod.rs` (lines 3-6: remove yaml/json exports, update `parse_rules`)
- Deprecate: `crates/waf-engine/src/rules/formats/yaml.rs` (add deprecation warn log)
- Deprecate: `crates/waf-engine/src/rules/formats/json.rs` (add deprecation warn log)
- Modify: `crates/waf-engine/src/rules/manager.rs` (lines 237: `import_from_url` uses yaml::parse)
- Modify: `crates/waf-engine/src/rules/registry.rs` (add new fields to `Rule` struct if needed for API compat)
- Possibly modify: `crates/waf-engine/src/rules/engine.rs` (extract `is_routing_header` to shared location)

## Implementation Steps

### Step 1: Add deprecation log to `yaml.rs::parse()`

Don't delete immediately — add deprecation warning:

```rust
pub fn parse(content: &str) -> Result<Vec<Rule>> {
    tracing::warn!("yaml::parse() is deprecated; migrate to custom_rule_v1 format");
    // ... existing logic unchanged
}
```

### Step 2: Add deprecation log to `json.rs::parse()`

Same approach.

### Step 3: Update `RuleManager::import_from_url`

At `manager.rs:237`, change fallback order:

```rust
// Try custom_rule_v1 first, then legacy yaml, then json
let rules = try_custom_rule_parse(&content)
    .or_else(|_| super::formats::yaml::parse(&content))
    .or_else(|_| super::formats::json::parse(&content))
    .with_context(|| format!("Failed to parse rules from {url}"))?;
```

Where `try_custom_rule_parse` converts custom_rule_v1 results to `Rule` for `RuleRegistry` compat.

**Alternative:** If `RuleManager` is only used for the admin API (listing/searching rules), and OWASP/advanced rules now load through `CustomRulesEngine` — `RuleManager::load_from_dir` may no longer need to parse `rules/advanced/` etc. Check caller chain.

### Step 4: Update `parse_rules()` in `formats/mod.rs`

```rust
pub fn parse_rules(content: &str, format: RuleFormat) -> Result<Vec<Rule>> {
    match format {
        RuleFormat::Yaml => {
            tracing::warn!("Registry YAML format deprecated; use custom_rule_v1");
            yaml::parse(content)
        }
        RuleFormat::ModSec => modsec::parse(content),
        RuleFormat::Json => {
            tracing::warn!("Registry JSON format deprecated; use custom_rule_v1");
            json::parse(content)
        }
    }
}
```

### Step 5: Extract `is_routing_header` to shared location

If both `owasp.rs` (before deletion) and `engine.rs` use it:

Option A: Move to `waf_common::request` module
Option B: Keep in `engine.rs` only (after Phase 4 deletes owasp.rs's copy)

**Choose Option B** — simpler, YAGNI.

### Step 6: Clean up dead imports

After Phase 4 removes code from `owasp.rs`, run:

```bash
cargo check 2>&1 | grep "unused import\|dead_code"
```

Fix all warnings.

### Step 7: Update `validate_rules()` in `formats/mod.rs`

Add validation that custom_rule_v1 rules have matching logic:

```rust
// For custom_rule_v1 parsed rules, validate:
// - has pattern OR conditions OR match_tree
// - pattern regex compiles
// - paranoia level in 1-4 range
```

### Step 8: `cargo fmt --all` and `cargo check`

## Common Pitfalls

- **Don't delete yaml.rs yet** — Remote rule sources (`import_from_url`) may still serve Registry format. Deprecate with warning first, delete in next release.
- **`Rule` struct compat** — The `RuleRegistry` uses `Rule` (not `CustomRule`). Admin API endpoints expose `Rule` fields. Ensure no API breakage.
- **Test breakage** — Tests in `mod.rs` use `yaml::parse`. Update or keep for deprecation coverage.

## Success Criteria

- [x] `yaml.rs::parse()` logs deprecation warning when called
- [x] `json.rs::parse()` logs deprecation warning when called
- [x] `RuleManager::import_from_url` tries custom_rule_v1 first
- [x] No dead code warnings from new changes
- [x] `is_routing_header()` exists in one location only
- [x] `cargo check` passes with zero warnings on changed files

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Breaking remote rule sources | Medium | Keep yaml.rs functional with deprecation log, don't delete |
| Admin API breakage | Medium | Verify Rule struct fields still match API responses |
| Missing imports after cleanup | Low | `cargo check` catches all |
