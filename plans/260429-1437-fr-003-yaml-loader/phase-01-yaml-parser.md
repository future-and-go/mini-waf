# Phase 01 — YAML Parser for FR-003 CustomRule

**Status:** complete  **Priority:** P2  **Effort:** 0.4d  **ACs:** parse + 6+ tests

## Context Links

- Schema reference: [`../../docs/custom-rules-syntax.md`](../../docs/custom-rules-syntax.md)
- JSON samples (mirror in YAML): [`../../rules/custom/fr003-samples/`](../../rules/custom/fr003-samples/)
- Existing engine types: `crates/waf-engine/src/rules/engine.rs` (`CustomRule`, `Condition`, `ConditionNode`, `ConditionOp`, `RuleAction`)

## Overview

Add a new module that parses YAML files containing FR-003 `CustomRule` definitions. Reuses existing serde-derived types in `engine.rs`. Validates the discriminator and the basic schema before returning. Does **not** compile rules (compilation happens at engine insert time, same as DB rules).

## Key Insights

- `serde_yaml` is already a workspace dep (used by `formats/yaml.rs`).
- `Condition`, `ConditionNode`, `ConditionField`, `Operator` already implement `Deserialize` with all the needed shape rules (cookie newtype, header newtype, etc.). **Do not duplicate those derives.**
- `CustomRule` itself does NOT currently implement `Deserialize` (only the engine fields are derived; the struct is built in `from_db_rule`). We need a sibling DTO.

## Requirements

### Functional

1. New file: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs`.
2. Public function:
   ```rust
   pub fn parse(content: &str) -> anyhow::Result<Vec<CustomRule>>;
   ```
3. Multi-document YAML supported (YAML stream — `serde_yaml::Deserializer::from_str` + iterate documents).
4. A document **without** top-level `kind: custom_rule_v1` returns `Ok(Vec::new())` for that document (silent skip — registry-format files in same directory).
5. A document **with** `kind: custom_rule_v1` but missing required fields returns `Err` with a context message naming the missing field.
6. Defaults applied:
   - `host_code` → `"*"`
   - `priority` → `0`
   - `enabled` → `true`
   - `condition_op` → `and`
   - `conditions` → `[]`
   - `match_tree` → `None`
   - `action_status` → `403`
   - `action_msg` → `None`
   - `script` → `None`
7. Required fields: `kind`, `name`. (Either `conditions` or `match_tree` may be empty — engine handles empty trees as no-match; warn at load time but don't fail.)
8. UUID for `id`: file rules don't have DB UUIDs. Use deterministic id derived from file basename + index, or accept user-provided `id: "string"` field. Choose: **user-provided `id` REQUIRED**, no auto-generation, to keep observability stable across reloads.

### Non-functional

- No `unwrap()` outside tests.
- No new heavy deps.

## Architecture

```
formats/
├── mod.rs                       # add `pub mod custom_rule_yaml;`
├── yaml.rs                      # existing registry-format parser
├── json.rs                      # existing
├── modsec.rs                    # existing
└── custom_rule_yaml.rs          # NEW
```

DTO:

```rust
#[derive(Debug, Deserialize)]
struct YamlCustomRule {
    kind: String,                   // must equal "custom_rule_v1"
    id: String,                     // required
    #[serde(default = "default_host")]
    host_code: String,              // "*"
    name: String,
    #[serde(default)]
    priority: i32,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    condition_op: ConditionOp,
    #[serde(default)]
    conditions: Vec<Condition>,
    #[serde(default)]
    match_tree: Option<ConditionNode>,
    #[serde(default = "default_action")]
    action: RuleAction,
    #[serde(default = "default_status")]
    action_status: u16,
    #[serde(default)]
    action_msg: Option<String>,
    #[serde(default)]
    script: Option<String>,
}
```

`parse()` flow:
1. `for doc in serde_yaml::Deserializer::from_str(content)`:
2. Try `serde_yaml::Value::deserialize(doc)`. Skip on err with `bail!`.
3. If top-level `kind` field missing or not `"custom_rule_v1"` → continue (skip silently).
4. Else `serde_yaml::from_value::<YamlCustomRule>(value)` with context.
5. Map DTO → `CustomRule { ... }`.
6. Append to result vector.

`RuleAction` already has `parse_str` but no `Deserialize`. Confirm: it has `#[derive(Deserialize)]` per engine.rs:208. ✓

`ConditionOp` already has `Default` + `Deserialize`. ✓

## Related Code Files

**Create:**
- `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs`

**Modify:**
- `crates/waf-engine/src/rules/formats/mod.rs` — add `pub mod custom_rule_yaml;`

**Read for context:**
- `crates/waf-engine/src/rules/engine.rs` (types)
- `crates/waf-engine/src/rules/formats/yaml.rs` (parser style precedent)

## Implementation Steps

1. Add module declaration in `formats/mod.rs`.
2. Define `YamlCustomRule` DTO + default fns.
3. Implement `parse()` with multi-doc + discriminator skip logic.
4. Map DTO → `CustomRule`.
5. Tests (see below).
6. `cargo check -p waf-engine` clean.
7. `cargo clippy -p waf-engine -- -D warnings` clean.

## Tests

In `#[cfg(test)] mod tests` at end of file:

1. `parse_minimal_v1_rule` — single doc with required fields only; defaults applied.
2. `parse_full_v1_rule_match_tree` — nested AND/OR/Not parses + condition values intact.
3. `parse_skips_doc_without_kind` — registry-format doc returns 0 rules, no error.
4. `parse_rejects_unknown_kind` — `kind: custom_rule_v999` → `Err` with context.
5. `parse_multi_doc_stream` — `---`-separated docs, mix of v1 and skipped, returns only v1s.
6. `parse_missing_id_errors` — required-field missing → `Err`.
7. `parse_cookie_newtype_field` — `field: {cookie: session}` → `ConditionField::Cookie(Some("session"))`.
8. `parse_invalid_match_tree_errors` — malformed tree node → `Err` with field path.

## Todo

- [x] Create `formats/custom_rule_yaml.rs` skeleton
- [x] Add module decl to `formats/mod.rs`
- [x] DTO + defaults
- [x] `parse()` impl
- [x] 8 tests
- [x] `cargo check` + `cargo clippy` clean

## Success Criteria

- All 8 tests pass.
- Clippy clean with `-D warnings`.
- `parse()` is the only public symbol from the module.
- File <200 LoC excluding tests.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| `Condition` serde shape changes break parser silently | New tests pin the cookie/header newtype shape; engine tests already cover serde |
| `serde_yaml` multi-doc API quirks | Use `for doc in Deserializer::from_str(s)` pattern; covered by test `parse_multi_doc_stream` |

## Next Steps

→ Phase 02: wire the parser into a file loader and call from `WafEngine::reload_rules`.
