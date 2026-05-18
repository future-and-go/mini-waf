---
phase: 4
title: "OWASPCheck Unification"
status: pending
priority: P1
effort: "8h"
dependencies: [2, 3]
---

# Phase 4: OWASPCheck Unification

## Overview

Replace `OWASPCheck`'s independent rule loading + evaluation pipeline with `CustomRulesEngine`. After Phase 3 migrates all YAML files to `custom_rule_v1`, the `OWASPCheck::from_directory()` → `RuleSet` → `CompiledRule` pipeline is redundant. This phase rewires OWASP Phase-13 to use the same `CustomRulesEngine` that Phase-12 (custom rules) uses.

This is the largest phase because `OWASPCheck` has its own compilation, field matching, URL-decode, paranoia filtering, and `pm_from_file` / `detect_sqli` / `detect_xss` special matchers that must be preserved.

## Requirements

- Functional: All 351 migrated rules evaluate identically before and after
- Functional: Paranoia-level filtering preserved (only evaluate rules where `paranoia <= config.owasp_paranoia`)
- Functional: Special matchers (`detect_sqli`, `detect_xss`, `pm_from_file`, `not_in`, `gt`, `lt`) preserved
- Functional: `field: "all"` skips routing headers + uses URL-decode (already in Phase 2)
- Non-functional: No performance regression (benchmark rule evaluation before/after)

## Architecture

```
BEFORE:
  Phase 12 (custom): CustomRulesEngine::check_with_verdict(ctx)
  Phase 13 (OWASP):  OWASPCheck::check(ctx, defense_config)  ← separate pipeline

AFTER:
  Phase 12+13 (unified): CustomRulesEngine::check_with_verdict(ctx)
                          ├── custom rules (from rules/custom/)
                          └── OWASP rules (from rules/advanced/, owasp-crs/, etc.)
                              filtered by paranoia level
```

**Key change:** `OWASPCheck` becomes a thin wrapper that:
1. Loads rules via `custom_rule_yaml::parse()` (they're now `custom_rule_v1`)
2. Inserts them into a dedicated `CustomRulesEngine` instance (or the shared one)
3. Filters by paranoia at eval time
4. Falls back to embedded rules if directory missing

## Related Code Files

- Modify: `crates/waf-engine/src/checks/owasp.rs` (~400 lines — major rewrite)
- Modify: `crates/waf-engine/src/rules/engine.rs` (paranoia filtering support)
- Modify: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` (special operator support)
- Read: `crates/waf-engine/src/checker.rs` (how OWASPCheck is called in Phase-13)

## Implementation Steps

### Step 1: Add special operators to `Operator` enum in `engine.rs`

OWASPCheck uses matchers not in `CustomRulesEngine`:

```rust
// Add to Operator enum (engine.rs)
DetectSqli,     // libinjection SQL injection detection
DetectXss,      // libinjection XSS detection
PmFromFile,     // Aho-Corasick multi-pattern from external file
NotIn,          // value not in list
Gt,             // greater than (numeric)
Lt,             // less than (numeric)
```

Most of these likely already exist (`Gt`, `Lt`, `NotIn` may already be in the `Operator` enum). Check before adding.

### Step 2: Add special matchers to `Matcher` enum and `compile_condition`

```rust
// In Matcher enum
DetectSqli,
DetectXss,
PmFromFile(String),  // filename reference

// In compile_condition
(Operator::DetectSqli, _) => Matcher::DetectSqli,
(Operator::DetectXss, _) => Matcher::DetectXss,
(Operator::PmFromFile, V::Str(s)) => Matcher::PmFromFile(s.clone()),
```

### Step 3: Add libinjection matching to `Matcher::matches()`

Port from `owasp.rs::CompiledMatcher::DetectSqli/DetectXss`:

```rust
Matcher::DetectSqli => {
    // Use libinjectionrs for SQL injection detection
    libinjectionrs::sqli(fstr).is_some()
}
Matcher::DetectXss => {
    libinjectionrs::xss(fstr).unwrap_or(false)
}
```

**Import:** `libinjectionrs` — check if already a dependency of `waf-engine`.

### Step 4: Add paranoia filtering to `CustomRulesEngine`

Option A — Filter at eval time (simpler, preferred):

```rust
/// Evaluate rules with paranoia-level filter.
pub fn check_with_verdict_filtered(
    &self,
    ctx: &RequestCtx,
    max_paranoia: Option<u8>,
) -> RuleVerdict {
    // Same as check_with_verdict but skip rules where
    // rule.paranoia > max_paranoia
    ...
}
```

Option B — Filter at load time (separate engine instance for OWASP):

```rust
// In OWASPCheck::new():
let engine = CustomRulesEngine::new();
for rule in loaded_rules {
    if rule.paranoia.unwrap_or(1) <= max_paranoia {
        engine.add_file_rule(rule);
    }
}
```

**Choose Option A** — simpler, allows paranoia changes at runtime without reload.

### Step 5: Rewrite `OWASPCheck` struct

```rust
pub struct OWASPCheck {
    engine: Arc<CustomRulesEngine>,
}

impl OWASPCheck {
    pub fn new(rules_root: &Path) -> Self {
        let engine = Arc::new(CustomRulesEngine::new());

        // Walk directory and load all custom_rule_v1 YAML files
        if rules_root.is_dir() {
            Self::load_recursive(rules_root, &engine);
        }

        if engine.is_empty() {
            // Fallback to embedded rules
            let embedded = custom_rule_yaml::parse(EMBEDDED_RULES_YAML)
                .unwrap_or_default();
            for rule in embedded {
                engine.add_file_rule(rule);
            }
        }

        Self { engine }
    }

    fn load_recursive(dir: &Path, engine: &CustomRulesEngine) {
        // Walk directory tree, parse each .yaml file via custom_rule_yaml::parse
        // Skip custom/ subdirectory (loaded separately by custom_file_loader)
        for entry in WalkDir::new(dir) ... {
            if path.contains("/custom/") { continue; }
            let content = fs::read_to_string(&path)?;
            match custom_rule_yaml::parse(&content) {
                Ok(rules) => {
                    for rule in rules {
                        engine.add_file_rule(rule);
                    }
                }
                Err(e) => warn!("Skipping {}: {e}", path.display()),
            }
        }
    }
}
```

### Step 6: Update `OWASPCheck::check()` to use `CustomRulesEngine`

```rust
impl Check for OWASPCheck {
    fn check(&self, ctx: &RequestCtx, config: &DefenseConfig) -> Option<DetectionResult> {
        let max_paranoia = config.owasp_paranoia;
        self.engine.check_with_verdict_filtered(ctx, Some(max_paranoia)).result
    }
}
```

### Step 7: Convert embedded fallback rules to `custom_rule_v1` format

The `EMBEDDED_RULES_YAML` constant uses Registry wrapper format. Convert to multi-doc `custom_rule_v1`:

```rust
const EMBEDDED_RULES_YAML: &str = r#"
kind: custom_rule_v1
id: BUILTIN-911100
name: Method is not allowed by policy
pattern_field: method
...
---
kind: custom_rule_v1
id: BUILTIN-920160
...
"#;
```

### Step 8: Delete dead code from `owasp.rs`

Remove: `RuleSet`, `YamlRule`, `YamlValue`, `CompiledMatcher`, old `CompiledRule` struct, `compile_rule()`, `is_routing_header()` (moved to engine.rs in Phase 2), `get_field()`, all the inline matching logic.

### Step 9: Run `cargo check` and fix

### Step 10: Run existing OWASP tests

Verify `crates/waf-engine/tests/` OWASP-related tests still pass.

## Common Pitfalls

- **`pm_from_file` matcher** — references external `.data` files (e.g., `ssrf.data`). The pattern evaluation must resolve these relative to the rules directory. This may need a rule-loading context.
- **`detect_sqli`/`detect_xss`** — libinjection checks the raw value, not against a regex. The `field: "all"` matching must call libinjection on each field value.
- **Paranoia level** — Rules without explicit paranoia default to 1. When `config.owasp_paranoia = 1` (default), only paranoia-1 rules run.
- **Embedded fallback** — Must convert the embedded YAML constant to `custom_rule_v1` format or the fallback breaks.
- **`custom/` directory exclusion** — OWASPCheck walks the entire `rules/` tree. It must skip `rules/custom/` since those are loaded separately by `custom_file_loader`.

## Success Criteria

- [ ] `OWASPCheck` uses `CustomRulesEngine` internally
- [ ] All 351 rules load through `custom_rule_yaml::parse()`
- [ ] Paranoia filtering works (paranoia 2+ rules skipped when config is 1)
- [ ] `detect_sqli`/`detect_xss` matchers work via `CustomRulesEngine`
- [ ] `pm_from_file` rules load without errors
- [ ] Embedded fallback works when `rules/` directory is missing
- [ ] Existing OWASP integration tests pass
- [ ] `cargo check` passes

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| OWASPCheck regression (351 rules) | High | Before/after test comparison with same request set |
| pm_from_file path resolution | Medium | Keep relative to rules directory; test with actual .data files |
| libinjection integration | Medium | Already used in OWASPCheck; just move to Matcher enum |
| Performance regression (351 rules through tree eval) | Medium | Pattern-only rules skip tree compilation; benchmark |
