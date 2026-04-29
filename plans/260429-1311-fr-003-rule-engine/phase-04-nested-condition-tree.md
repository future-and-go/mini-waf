# Phase 04 — Nested AND/OR Condition Tree (Composite)

**Status:** complete  **Priority:** P0  **Effort:** 1d  **ACs:** AC-8 (nested AND/OR)

## Context Links
- Design: brainstorm §3.2, §3.3 YAML schema, §5 row 8
- Touch: `crates/waf-engine/src/rules/engine.rs`, `crates/waf-engine/src/rules/formats/{yaml,json}.rs`, `crates/waf-engine/src/rules/manager.rs`

## Overview
Replace flat `condition_op + Vec<Condition>` with optional `match_tree: Option<ConditionNode>` recursive enum (Composite pattern). Legacy rules remain valid — adapter wraps them. Parsers (YAML + JSON) accept BOTH shapes.

## Key Insights
- **Composite pattern**: tree node is uniform — `Leaf`, `And`, `Or`, `Not`. Eval is straightforward recursion.
- Schema migration is in-app (JSON column in DB, no DDL): from_db_rule detects shape by JSON structure.
- Single-rule expressivity: `(country=CN AND ua~bot) OR ip in blacklist` becomes one rule, was two.

## Requirements

### Functional
1. Add optional `match_tree: Option<ConditionNode>` to `CustomRule`. If present, takes precedence over flat `conditions`.
2. `compile_rule()` chooses tree if present, else falls back to flat-as-And/Or wrap.
3. YAML parser accepts both legacy and new `match:` schemas (brainstorm §3.3).
4. JSON parser ditto — branches on presence of `match` key vs `conditions`.
5. `from_db_rule()`: detect new schema by presence of `match_tree` key in JSON; fall back to flat array → `And`/`Or` wrap.
6. AC-8 test: rule `(ip in CIDR OR cookie=bad) AND path=/api/*/admin` evaluates per truth table.

### Non-Functional
- Parser fuzz-resistant: malformed nested structure returns `Err` with line context (serde default).
- Tree depth limit: reject `match_tree` with depth > 16 (DoS guard at compile).

## Architecture

```rust
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionNode {
    Leaf(Condition),
    And(Vec<ConditionNode>),
    Or(Vec<ConditionNode>),
    Not(Box<ConditionNode>),
}

pub struct CustomRule {
    // …existing
    pub match_tree: Option<ConditionNode>,   // new — preferred when present
}
```

YAML grammar (recursive):
```yaml
match:
  or:
    - {field: ip, op: cidr_match, value: 10.0.0.0/8}
    - and:
        - {field: cookie, name: session, op: eq, value: bad}
        - {field: path, op: wildcard, value: "/api/*/admin"}
```

Serde tag strategy: serialize `ConditionNode` as untagged enum with discriminator keys (`and`/`or`/`not`/leaf-by-shape). Use `#[serde(untagged)]` and rely on key-presence disambiguation.

## Related Code Files
**Modify:**
- `crates/waf-engine/src/rules/engine.rs` — `ConditionNode`, `CustomRule.match_tree`, depth check, `compile_rule()` tree-aware path.
- `crates/waf-engine/src/rules/formats/yaml.rs` — accept `match:` key alongside legacy `conditions:`.
- `crates/waf-engine/src/rules/formats/json.rs` — same.
- `crates/waf-engine/src/rules/manager.rs` — pass tree into compile.
- `from_db_rule()` — JSON shape detection + adapter.

## Implementation Steps
1. Add `ConditionNode` with `Serialize + Deserialize`. Verify YAML/JSON round-trip via tests.
2. Add depth-check helper `validate_depth(node, max=16) -> Result<()>` invoked in `compile_rule()`.
3. `compile_rule()`: if `match_tree.is_some()` → compile tree directly; else → wrap flat conditions as before.
4. Implement `compile_tree(&ConditionNode) -> Result<CompiledNode>` (mirror tree shape, swap `Condition`→`CompiledCondition`).
5. YAML parser:
   - Add `match: Option<ConditionNode>` to raw struct alongside legacy `conditions`/`condition_op`.
   - Reject if both keys present (ambiguous).
6. JSON parser: same dual-key strategy.
7. `from_db_rule()`: probe JSON value — if shape is `{ "match_tree": ... }` → deserialize tree; else legacy array → wrap.
8. Tests:
   - YAML round-trip nested
   - JSON round-trip nested
   - Both-keys-rejected
   - Depth-exceeded rejected
   - Legacy DB rule still compiles + matches
   - AC-8 truth table (4 cases: TT, TF, FT, FF)

## Todo
- [x] `ConditionNode` enum + serde
- [x] Depth validation (max 16)
- [x] `compile_tree()` recursive compiler
- [x] YAML parser dual-shape
- [x] JSON parser dual-shape
- [x] `from_db_rule()` shape detection
- [x] 8+ tests covering AC-8 truth table + parser shapes

## Success Criteria
- AC-8 truth table passes (all 4 combos correct).
- Existing legacy rules (DB + sample YAML) evaluate identically (regression).
- Both parsers accept new schema; both reject ambiguous double-key rules.

## Security
- Depth limit 16 prevents stack-blow from adversarial nested rule.
- Leaf count cap per tree (e.g., 256) — defensive; logged at compile.
- Parser uses serde's bounded recursion; no eval-time allocation.
