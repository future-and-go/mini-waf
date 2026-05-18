---
phase: 2
title: "Pattern Evaluation Engine"
status: done
priority: P1
effort: "6h"
dependencies: [1]
---

# Phase 2: Pattern Evaluation Engine

## Overview

Add pattern-based matching to `CustomRulesEngine::eval_list_with_verdict()`. When a rule has a `pattern` field (compiled `Regex`), evaluate it against the request field specified by `pattern_field`. This reuses OWASPCheck's proven field-targeting approach (`"all"`, `"path"`, `"query"`, `"body"`, etc.) including URL-decode bypass protection.

## Requirements

- Functional: Pattern rules must match the same requests as OWASPCheck's equivalent regex rules
- Functional: `field: "all"` must skip routing headers (Host, :authority, etc.) — same as OWASPCheck
- Functional: URL-decoded variants must be checked to prevent encoding bypasses
- Non-functional: Pattern eval is last resort after match_tree/conditions/script; no perf regression for existing rules

## Architecture

Evaluation precedence in `eval_list_with_verdict` (updated):

```
1. Rhai script (if present) — legacy escape hatch
2. Compiled match_tree (preferred)
3. Legacy flat conditions
4. Pattern + field (NEW — fallback when no conditions/match_tree)
5. Operator shorthand → auto-converted to condition at parse time (NEW)
```

The `field: "all"` logic is ported directly from `OWASPCheck::CompiledRule::matches()` at `owasp.rs:159-210` — including `is_routing_header()` skipping and recursive URL-decode.

## Related Code Files

- Modify: `crates/waf-engine/src/rules/engine.rs` (lines 432-478: `eval_list_with_verdict`, lines 710-730: `compile_rule`)
- Modify: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs` (`to_custom_rule` — operator/value auto-conversion)
- Read: `crates/waf-engine/src/checks/owasp.rs` (lines 112-210 — reference for field matching logic)

## Implementation Steps

### Step 1: Add `pattern_matches_request()` to `engine.rs`

Port the field-matching logic from `owasp.rs::CompiledRule::matches()`. Place as a free function near `eval_compiled_node`:

```rust
/// Check if a compiled regex pattern matches the specified request field(s).
///
/// When field is "all", checks path → query → body → non-routing headers
/// with URL-decode bypass protection (same logic as OWASPCheck).
fn pattern_matches_request(pattern: &Regex, field: &str, ctx: &RequestCtx) -> bool {
    match field {
        "path" => test_with_decode(pattern, &ctx.path),
        "query" => test_with_decode(pattern, &ctx.query),
        "body" => test_with_decode(pattern, &String::from_utf8_lossy(&ctx.body_preview)),
        "method" => pattern.is_match(&ctx.method),
        "cookies" => ctx.cookies.iter().any(|(_, v)| test_with_decode(pattern, v)),
        "headers" => ctx.headers.iter()
            .filter(|(k, _)| !is_routing_header(k))
            .any(|(_, v)| test_with_decode(pattern, v)),
        "all" | _ => {
            // Short-circuit: smallest fields first (path < query < headers < body)
            test_with_decode(pattern, &ctx.path)
                || test_with_decode(pattern, &ctx.query)
                || ctx.headers.iter()
                    .filter(|(k, _)| !is_routing_header(k))
                    .any(|(_, v)| test_with_decode(pattern, v))
                || test_with_decode(pattern, &String::from_utf8_lossy(&ctx.body_preview))
        }
    }
}

/// Test a value against a regex, trying URL-decoded variants to prevent bypass.
fn test_with_decode(pattern: &Regex, raw: &str) -> bool {
    if pattern.is_match(raw) {
        return true;
    }
    let decoded = url_decode(raw);
    if decoded != raw && pattern.is_match(&decoded) {
        return true;
    }
    let recursive = url_decode_recursive(raw);
    recursive != decoded && pattern.is_match(&recursive)
}
```

**Import:** `use super::super::checks::{url_decode, url_decode_recursive};` (reuse existing functions from checks module).

### Step 2: Port `is_routing_header()` to engine.rs

Copy from `owasp.rs:118-134`:

```rust
fn is_routing_header(name: &str) -> bool {
    matches!(
        name,
        "host" | ":authority" | ":method" | ":path" | ":scheme"
            | "accept" | "accept-encoding" | "accept-language"
            | "connection" | "content-length"
            | "x-forwarded-host" | "x-real-ip"
    )
}
```

**Alternative:** Extract to `waf_common` if shared between owasp.rs and engine.rs. Consider DRY — but YAGNI says copy for now, refactor in Phase 5.

### Step 3: Update `eval_list_with_verdict()` — add pattern fallback

At `engine.rs:443-451`, add pattern check as step 4:

```rust
let matched = rule.script.as_ref().map_or_else(
    || {
        entry.compiled.as_ref().map_or_else(
            || {
                // Try legacy flat conditions first
                if !rule.conditions.is_empty() {
                    self.eval_conditions(ctx, &rule.conditions, &rule.condition_op)
                } else if let Some(ref pattern) = rule.pattern {
                    // NEW: pattern fallback
                    pattern_matches_request(pattern, &rule.pattern_field, ctx)
                } else {
                    false
                }
            },
            |compiled| eval_compiled_node(ctx, &compiled.root),
        )
    },
    |script| self.eval_script(ctx, script),
);
```

### Step 4: Auto-convert operator+value shorthand to condition at parse time

In `custom_rule_yaml.rs::to_custom_rule()`, when `operator` and `value` are present but no `conditions`/`match_tree`:

```rust
// Auto-convert Registry-style field+operator+value to a condition
let mut conditions = dto.conditions;
if conditions.is_empty() && dto.match_tree.is_none() && dto.pattern.is_none() {
    if let (Some(op_str), Some(val)) = (&dto.operator, &dto.value) {
        let field = parse_condition_field(&dto.pattern_field);
        let operator = parse_operator(op_str);
        let value = yaml_value_to_condition_value(val);
        conditions.push(Condition { field, operator, value });
    }
}
```

This handles Registry rules that use `field: "body"`, `operator: "contains"`, `value: "payload"` format.

### Step 5: Update `compile_rule()` to handle pattern-only rules

Currently, if `match_tree` is None and `conditions` is empty, `compile_rule` produces an empty `And(vec![])` root. Update to handle the pattern-only case — pattern rules don't need compiled tree:

```rust
pub fn compile_rule(rule: &CustomRule) -> anyhow::Result<CompiledRule> {
    let root = if let Some(tree) = rule.match_tree.as_ref() {
        validate_tree(tree)?;
        compile_tree(tree)?
    } else if !rule.conditions.is_empty() {
        // existing flat-conditions logic
        let leaves = ...;
        match rule.condition_op { ... }
    } else {
        // Pattern-only or always-match: empty And is fine,
        // eval fallback handles pattern in eval_list_with_verdict
        CompiledNode::And(vec![])
    };
    Ok(CompiledRule { meta: rule.clone(), root })
}
```

### Step 6: Run `cargo check` and fix

## Common Pitfalls

- **Forgetting URL-decode** — Without it, `%7B%7B7%2A7%7D%7D` bypasses SSTI rules. Always check decoded variants.
- **Routing headers in "all"** — Must skip `host`, `:authority`, etc. or SSRF rules FP on every request to `localhost`.
- **Eval order** — Pattern must be LAST resort. If conditions exist, use those; pattern is only when no other logic present.
- **Empty conditions AND no pattern** — Log warning, don't match. Current code returns `false` for empty conditions — keep that behavior.

## Success Criteria

- [x] Rules with `pattern: "..."` and `pattern_field: "body"` match body content
- [x] Rules with `pattern_field: "all"` check path, query, headers (excluding routing), body
- [x] URL-decode bypass protection works (encoded payloads still match)
- [x] Rules with operator+value shorthand auto-convert to conditions
- [x] Existing custom rules (conditions/match_tree) unaffected
- [x] `cargo check` passes

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Pattern matches unintended fields | High | Explicit field targeting; skip routing headers for "all" |
| URL-decode doubles regex cost | Medium | Short-circuit: skip decode if raw already matched |
| Performance regression on "all" field | Medium | Check smallest fields first (path → query → headers → body) |
