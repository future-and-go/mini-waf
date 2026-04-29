# Phase 01 — Schema + Compile Step (No Behavior Change)

**Status:** done  **Priority:** P0  **Effort:** 0.5d  **ACs:** scaffold for AC-1..8

## Context Links
- Design: [`../reports/brainstorm-260429-1303-fr-003-rule-engine.md`](../reports/brainstorm-260429-1303-fr-003-rule-engine.md) §3.2
- Touch: `crates/waf-engine/src/rules/engine.rs`

## Overview
Introduce new types (`ConditionNode`, `CompiledNode`, `CompiledCondition`, `Matcher`) alongside existing flat ones — no eval path change yet. Add `compile_rule()` adapter that wraps legacy `Vec<Condition>` as `And([Leaf,...])`. All existing tests must continue to pass unchanged.

## Key Insights
- **Composite pattern**: recursive `CompiledNode` enables nested AND/OR/Not without flag soup.
- **Adapter pattern**: legacy flat conditions auto-promoted to `And` tree → zero DB migration.
- New types live behind `compile_rule()` boundary; eval still goes through the old path until phase 04 flips it.

## Requirements

### Functional
1. Add types per brainstorm §3.2 — `ConditionNode`, `CompiledRule`, `CompiledNode`, `CompiledCondition`, `Matcher`.
2. `compile_rule(rule: &CustomRule) -> Result<CompiledRule>` returns a tree wrapping legacy flat conditions as `And([Leaf,...])` (or `Or` per `condition_op`).
3. Compile errors (bad regex, bad CIDR) logged via `tracing::warn` and bubbled up — caller decides whether to skip.

### Non-Functional
- Zero behavior change for existing rules (regression tests pass).
- No clippy warnings; no `.unwrap()` in production paths.

## Architecture

```
CustomRule (raw, persistent)         ─compile_rule()─►   CompiledRule (eval-ready)
  conditions: Vec<Condition>                              root: CompiledNode (tree)
  condition_op: ConditionOp
  + (later) match_tree: Option<ConditionNode>             Matcher pre-compiled inline
```

`Matcher` variants pre-compile heavy state:
- `Regex(regex::Regex)` — compiled once
- `Glob(globset::GlobMatcher)` — phase 02
- `InList(ahash::HashSet<String>)` — O(1) lookup
- `Cidr(ipnet::IpNet)` — parsed once

## Related Code Files
**Modify:**
- `crates/waf-engine/src/rules/engine.rs` — add types + `compile_rule()`; keep legacy eval untouched.
- `crates/waf-engine/Cargo.toml` — `ahash = "0.8"` (already?), no new heavy deps yet.

**Read for context:**
- `crates/waf-storage/src/models/custom_rule.rs` — DB schema reference.
- `crates/waf-common/src/lib.rs` — `RequestCtx` shape.

## Implementation Steps
1. Add `ConditionNode` enum (Leaf/And/Or/Not) — derive `Serialize/Deserialize` (kept absent on storage path until phase 04 — opt-in).
2. Add `CompiledNode` + `CompiledCondition` + `Matcher` enums — **not** serializable (in-memory only).
3. Implement `compile_rule(&CustomRule) -> Result<CompiledRule>`:
   - If rule has no `match_tree` (phase 01: always None), wrap `conditions` per `condition_op`.
   - Each `Condition` → `CompiledCondition` via `compile_condition()` which selects `Matcher` variant from `Operator`.
4. Implement `compile_condition(&Condition) -> Result<CompiledCondition>` — covers Eq/Ne/Contains/NotContains/StartsWith/EndsWith/Regex/InList/NotInList/CidrMatch/Gt/Lt/Gte/Lte. Wildcard returns `Err` (added phase 02).
5. Unit tests: legacy AND/OR flat shape compiles to expected tree; bad regex returns Err; bad CIDR returns Err.
6. Run `cargo check -p waf-engine && cargo clippy -p waf-engine --all-targets -- -D warnings && cargo test -p waf-engine`.

## Todo
- [x] Add `ConditionNode`, `CompiledRule`, `CompiledNode`, `CompiledCondition`, `Matcher` types
- [x] Implement `compile_rule()` + `compile_condition()` (legacy adapter path)
- [x] Unit tests: 6 cases (compile success/failure shapes)
- [x] `cargo check && clippy && test` green

## Success Criteria
- All new types present, derives intact.
- `compile_rule(legacy_rule)` produces `And`/`Or` tree of `Leaf`s with correct matcher variants.
- Zero existing test breaks.

## Security
- Regex compile uses upstream `regex` crate's default size/complexity limits — DoS via pathological regex rejected at compile time.
- CIDR parsed via `ipnet` — no string scan on hot path.
