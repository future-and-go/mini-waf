# Phase 02 — Wildcard Operator + Matcher Strategy Wired

**Status:** done  **Priority:** P0  **Effort:** 0.5d  **ACs:** AC-3 (path wildcard)

## Context Links
- Design: brainstorm §3.1, §3.2, §5 row 3
- Touch: `crates/waf-engine/src/rules/engine.rs`, `crates/waf-engine/Cargo.toml`

## Overview
Add `Operator::Wildcard` variant + `Matcher::Glob(globset::GlobMatcher)` pre-compiled. Wire `compile_condition()` to compile glob once. Flip eval to walk `CompiledNode` tree for rules that have a compiled tree (introduced phase 01); legacy still evaluable through compiled adapter.

## Key Insights
- `globset` already pulled transitively via `ignore` → adding direct dep is free.
- Glob `*` does NOT cross `/` (matches `globset::Glob::default`); use `**` for path-spanning. Documented in phase 06.
- **Strategy pattern in action**: each `Matcher` variant owns its evaluation; one `match_value()` dispatch instead of N nested `match` arms.

## Requirements

### Functional
1. `Operator::Wildcard` variant added.
2. `Matcher::Glob(GlobMatcher)` compiled in `compile_condition()`.
3. `eval_compiled_node(ctx, &CompiledNode)` recursive evaluator added — used when rule has compiled tree; replaces flat eval gradually.
4. Wildcard matches per AC-3: `/api/*/admin` matches `/api/v1/admin`, misses `/api/admin`.

### Non-Functional
- Compile cost amortized: matcher compiled once per rule load, not per request.
- Glob compile failure → rule skipped + warn log (not crash).

## Architecture

```rust
pub enum Operator { /* …, */ Wildcard }

pub enum Matcher {
    Eq(String), Ne(String), Contains(String), NotContains(String),
    StartsWith(String), EndsWith(String),
    Regex(regex::Regex),
    Glob(globset::GlobMatcher),
    InList(HashSet<String>), NotInList(HashSet<String>),
    Cidr(ipnet::IpNet),
    Gt(i64), Lt(i64), Gte(i64), Lte(i64),
}

impl Matcher {
    fn matches(&self, fstr: &str, ctx_ip: IpAddr) -> bool { /* dispatch */ }
}
```

`eval_compiled_node`:
- `Leaf(c)`  → `c.matcher.matches(field_value(ctx, &c.field), ctx.client_ip)`
- `And(v)`   → `v.iter().all(|n| eval_compiled_node(ctx, n))`
- `Or(v)`    → `v.iter().any(|n| eval_compiled_node(ctx, n))`
- `Not(b)`   → `!eval_compiled_node(ctx, b)`

## Related Code Files
**Modify:**
- `crates/waf-engine/Cargo.toml` — `globset = "0.4"` direct dep.
- `crates/waf-engine/src/rules/engine.rs` — `Wildcard` variant; `Matcher::matches`; `eval_compiled_node`.
- `crates/waf-engine/src/rules/manager.rs` — call `compile_rule()` before insert; store compiled tree alongside raw rule.

## Implementation Steps
1. `Cargo.toml`: add `globset = "0.4"`.
2. Extend `Operator` with `Wildcard`. Update `serde` rename map if needed.
3. Extend `Matcher` with `Glob(GlobMatcher)`.
4. Update `compile_condition()` to handle Wildcard → `Glob(Glob::new(pat)?.compile_matcher())`.
5. Add `Matcher::matches(fstr, ctx_ip)` — single dispatch table.
6. Add `eval_compiled_node()` recursive evaluator.
7. Update `eval_list()` to prefer compiled tree path; legacy path retained as fallback during migration.
8. Tests:
   - `wildcard_glob_matches_segment` (AC-3)
   - `wildcard_does_not_cross_slash`
   - `wildcard_compile_failure_returns_err`
   - `matcher_dispatch_table` (each variant exercised)
9. `cargo check && clippy && test`.

## Todo
- [x] Add `globset` dep
- [x] `Operator::Wildcard` + serde
- [x] `Matcher::Glob` + compile path
- [x] `Matcher::matches` dispatch
- [x] `eval_compiled_node` recursive evaluator
- [x] engine: call `compile_rule` on `add_rule`/`load_host` (`RuleEntry`)
- [x] 4+ unit tests pass (5 new: wildcard segment match, no slash crossing, compile failures, dispatch table, compiled-path eval)

## Success Criteria
- AC-3 test passes (glob path match + no slash crossing).
- All other operators continue to evaluate identically (regression).
- Compile cost paid once at load, not per request.

## Security
- Reject empty patterns and bare `**` (catches accidental "match everything"). Returns compile error.
- `globset` size limited by upstream defaults; no recursive blow-up.
