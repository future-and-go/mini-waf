---
phase: 1
title: "Regex Pre-Compilation Guarantee"
finding: F2
status: pending
priority: P1
effort: "2h"
dependencies: []
---

# Phase 1: Regex Pre-Compilation Guarantee

## Overview

Per-request `Regex::new()` at `rules/engine.rs:754` compiles regex on every match attempt when `compiled` is `None`. Pre-compile all regex at rule load time; make the fallback path unreachable. Hard error on invalid regex at load prevents silent fail-open.

## Key Insights

- `compile_condition()` (engine.rs:1006-1011) already compiles regex into `Matcher::Regex(re)` at load time
- The hot path `eval_compiled_node()` (engine.rs:1203) uses pre-compiled matchers — no regex allocation
- Problem: when `compile_rule()` fails, `from_rule_with_source()` (engine.rs:339) inserts rule with `compiled: None` + `warn!`
- Fallback: `eval_one()` (engine.rs:743) runs `Regex::new(v)` per request at line 754 for these rules
- Dual eval path at engine.rs:691-701: `entry.compiled.as_ref().map_or_else(|| self.eval_conditions(...), |compiled| eval_compiled_node(...))`
- **RED-TEAM FIX**: `from_rule_with_source()` returns `Self` (not `()`). Cannot `return;` on error. Must change return type to `Option<Self>` and fix all callers: `from_rule()` (line 334), `insert_rule()` (line 434), `load_host()` (line 411 via `from_rule()` + `filter_map`)
- **RED-TEAM FIX**: `eval_one()` CidrMatch at line 757 has same per-request `cidr.parse::<IpNet>()` — apply same `error!` + return false treatment
- **RED-TEAM FIX**: Use `error!()` + return false in `eval_one()` instead of `debug_assert!(false)` — debug_assert panics in test builds
- Research: ~50x speedup per match by eliminating runtime compilation

## Requirements

**Functional:**
- All regex conditions pre-compiled at rule load via `compile_rule()`
- Invalid regex fails loudly at load (hard error) — rule rejected, not inserted with `compiled: None`
- `eval_one()` regex arm must never allocate — use `debug_assert!` + return false

**Non-functional:**
- Zero regex compilation in hot eval loop
- No memory regression (one `Regex` per condition, already budgeted by `Matcher::Regex`)

## Architecture

**Data flow:**
```
Rule JSON → CustomRule → compile_rule() → CompiledRule(Matcher::Regex) → eval_compiled_leaf()
                              ↓ (fail)
                         hard error → rule rejected, error! log, rule skipped
```

**Current fallback path (to eliminate):**
```
eval_one():754 → Regex::new(v) per request → REMOVE
```

## Related Code Files

| File | Action | LOC Est. | Test Impact |
|------|--------|----------|-------------|
| `crates/waf-engine/src/rules/engine.rs` | Modify | ~15 changed | Add 3 tests |

## Tests Before (TDD)

Write these FIRST, before refactoring:

1. **Test: compiled=None fallback with regex condition does NOT compile at runtime**
   - Create `RuleEntry` with `compiled: None` and a `Condition` using `Operator::Regex`
   - Call eval path for that entry
   - Assert: returns `false` (fail-closed), does NOT succeed on matching input

2. **Test: invalid regex at load time returns Err from compile_condition()**
   - Call `compile_condition()` with `Operator::Regex`, value `"[invalid"`
   - Assert: returns `Err`, not silent skip

3. **Test: valid regex compiles at load and matches at eval**
   - `compile_rule()` with regex condition `"^admin.*"`
   - Assert: `compiled` is `Some`, contains `Matcher::Regex`
   - Eval against `"admin/login"` → true
   - Eval against `"user/profile"` → false

## Implementation Steps

1. **Verify `compile_condition` handles regex** — confirmed at engine.rs:1006-1011: `regex::RegexBuilder::new(s).size_limit(1 << 20).build().with_context(...)`. Correct, no changes needed.

2. **Change `from_rule_with_source()` return type** (engine.rs:338-352):
   - **RED-TEAM**: `from_rule_with_source()` returns `Self`, not `()`. Cannot use bare `return;`.
   - Change return type to `Option<Self>`. On compile error: `error!()` + return `None`.
   ```rust
   // BEFORE: fn from_rule_with_source(...) -> Self
   // AFTER:  fn from_rule_with_source(...) -> Option<Self>
   let compiled = match compile_rule(&rule) {
       Ok(c) => c,
       Err(e) => {
           error!(rule_id = %rule.id, error = %e, "Rule rejected: compile failed");
           return None;
       }
   };
   // ... build entry ...
   Some(entry)
   ```

3. **Fix all callers of `from_rule_with_source()`**:
   - `from_rule()` (line 334): change to return `Option<Self>`, propagate
   - `load_host()` (line 411): uses `from_rule()` in iterator — change to `.filter_map(|r| RuleEntry::from_rule(r))`
   - `insert_rule_tracked()` (line 445-474): on `None` from `from_rule_with_source()`, log `error!`, skip insertion

4. **Remove runtime regex AND CidrMatch from `eval_one()`** (engine.rs:754-757):
   - **RED-TEAM**: Use `error!()` + return false, NOT `debug_assert!` (panics in test builds)
   ```rust
   // BEFORE:
   (Operator::Regex, ConditionValue::Str(v)) => Regex::new(v).ok().is_some_and(|r| r.is_match(fstr)),
   
   // AFTER:
   (Operator::Regex, _) => {
       error!("BUG: regex condition reached uncompiled eval_one");
       false
   }
   // Also fix CidrMatch at line 757 (same per-request parsing issue):
   (Operator::CidrMatch, _) => {
       error!("BUG: cidr condition reached uncompiled eval_one");
       false
   }
   ```

5. **Run regression gate**

## Refactor

Changes (~30 lines):
- `engine.rs:338`: `from_rule_with_source()` → return `Option<Self>`, `None` on compile error
- `engine.rs:334`: `from_rule()` → return `Option<Self>`, propagate
- `engine.rs:411`: `load_host()` → `.filter_map(|r| RuleEntry::from_rule(r))`
- `engine.rs:445-474`: `insert_rule_tracked()` → handle `None` from `from_rule_with_source()`
- `engine.rs:754`: replace `Regex::new(v)` with `error!(...); false`
- `engine.rs:757`: replace `cidr.parse()` with `error!(...); false`

## Tests After (TDD)

1. **Test: rule with invalid regex is NOT loaded into engine**
   - `add_rule()` with broken regex pattern
   - Assert: rule absent from engine's DashMap
   - Assert: no panic, error logged

2. **Test: eval_one regex arm returns false (not panic in release)**
   - Construct a `Condition` with `Operator::Regex`, call `eval_one()` directly
   - Assert: returns `false`

## Regression Gate

```bash
cargo check -p waf-engine
cargo test -p waf-engine -- --nocapture
```

## Success Criteria

- [ ] `Regex::new()` removed from `eval_one()` hot path
- [ ] Invalid regex at load → rule rejected with `error!` log
- [ ] All 172 existing tests pass
- [ ] 3+ new tests added and passing
- [ ] `cargo check -p waf-engine` clean (zero warnings)

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Rules relying on runtime regex fallback silently break | Low | High | Audit: `compile_rule` already compiles regex; only broken patterns hit fallback |
| Pattern-only rules (no conditions) affected | None | — | Pattern-only rules use `pattern_matches_request()` not `eval_one()` |
| Existing tests use `compiled: None` intentionally | Low | Medium | Check test fixtures; they use `unwrap()` (allowed in `#[cfg(test)]`) |

## Test Scenario Matrix

| Scenario | Priority | Type |
|----------|----------|------|
| Valid regex compiles at load, matches at eval | Critical | Unit |
| Invalid regex rejects rule at load | Critical | Unit |
| compiled=None + regex operator → false | Critical | Unit |
| Pattern-only rule unaffected | High | Unit |
| Existing 172 tests regression | High | Regression |

## Dependency Map

- **Depends on**: nothing
- **Blocks**: Phase 7 (integration)
- **File ownership**: `crates/waf-engine/src/rules/engine.rs` — exclusive to this phase
