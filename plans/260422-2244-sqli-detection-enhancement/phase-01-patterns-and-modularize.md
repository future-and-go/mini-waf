# Phase 01 — Pattern Additions + Modularization

## Priority
P0 — foundation for later phases.

## Objective
Add blind + error-based patterns. Split the monolithic file into 3 modules, each under 200 lines.

## Files to Create
- `crates/waf-engine/src/checks/sql_injection_patterns.rs` — `RegexSet` + aligned description slice (pure data, ~80 lines)
- `crates/waf-engine/src/checks/sql_injection_scanners.rs` — stub for Phase 02/03 helpers (skeleton only this phase)

## Files to Modify
- `crates/waf-engine/src/checks/sql_injection.rs` — remove inline patterns, import from `_patterns` module
- `crates/waf-engine/src/checks/mod.rs` — declare new submodules (still re-export `SqlInjectionCheck`)

## Patterns to Add (append to existing `SQLI_SET`)

| Category | Pattern | Description |
|---|---|---|
| boolean-blind | `(?i)\b(and\|or)\s+\d+\s*(=\|<\|>)\s*\d+\b` | numeric tautology (`AND 1=1`, `OR 2>1`) |
| blind-extract | `(?i)\b(substring\|substr\|mid\|ascii\|length\|hex\|bin)\s*\(` | blind data-extraction funcs |
| blind-cond | `(?i)\bif\s*\([^)]{1,128}?,[^)]{1,128}?,[^)]{1,128}?\)` | conditional blind `IF(x,y,z)` |
| fingerprint | `(?i)@@(version\|datadir\|hostname\|tmpdir\|servername)\b` | DB fingerprint |
| error-based-cast | `(?i)\bcast\s*\([^)]{1,64}?\s+as\s+` | error-based CAST |
| error-based-conv | `(?i)\bconvert\s*\([^)]{1,64}?using\s+` | MySQL error-based CONVERT |
| error-based-dbl | `(?i)\bexp\s*\(\s*~\s*\(` | MySQL DOUBLE overflow |

Bound repetition explicitly (`{1,128}?`) to prevent ReDoS. Non-greedy.

## Descriptions (aligned by index)
Extend `SQLI_DESCS` in lockstep. Every new pattern index gets a matching description — enforce with a compile-time `assert_eq!(SQLI_DESCS.len(), /*expected*/)` in `fn check` or via `const_assert`.

## Rule ID Stability
Existing patterns keep their `SQLI-001..SQLI-012` IDs. New patterns append as `SQLI-013..SQLI-019`. Do NOT reorder. Downstream (dashboards, aggregation SQL in `waf-storage/src/repo.rs:974`) depends on prefix only, but IDs are also user-visible in attack logs.

## Todo
- [x] Create `sql_injection_patterns.rs` with full `SQLI_SET` + `SQLI_DESCS` (including new rows)
- [x] `pub use` those from `sql_injection.rs`
- [x] Create empty `sql_injection_scanners.rs` with module-level doc comment
- [x] Wire both modules in `checks/mod.rs`
- [x] `cargo check -p waf-engine`
- [x] `cargo clippy -p waf-engine -- -D warnings`
- [x] Run existing tests: `cargo test -p waf-engine sql_injection`

## Success Criteria
- All existing SQLi tests still pass
- `cargo check` green, no new clippy warnings
- Each file under 200 lines
- New patterns each covered by a pattern-targeted unit test (≥7 new tests)

## Risks
- ReDoS from unbounded alternation → already mitigated via `{1,N}?` bounds
- Rule ID collision with YAML rules in `rules/` → grep `rules/` for `SQLI-013` through `SQLI-019` before assigning

## Non-Regressions
- `Phase::SqlInjection` unchanged
- `request_targets` helper untouched (that's Phase 02's job)
- `defense_config.sqli` toggle still works
