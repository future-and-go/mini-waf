---
phase: 3
title: "risk module"
status: pending
effort: "0.75d"
priority: P1
dependencies: [1, 2]
---

# Phase 3: risk module

## Overview

Smallest semantic surface (one root key `risk:`, ~5 sub-tables, no sequences) and **also has** an admin API path, making it the right pilot. After this phase, the pattern is locked in for Phases 4–7. TDD: rewrite the unit tests in `risk/config.rs` with TOML fixtures and one Phase-1 equivalence test, then swap the parser, then write `configs/risk.toml` + delete `configs/risk.yaml`.

## Requirements

- Functional: `RiskConfig::from_path(p)` reads `*.toml` (file extension agnostic — content is what matters; path is whatever the caller passes).
- Functional: `RiskReloader` continues to watch the file by name; integration test rewrites the file and asserts ArcSwap pointer swap within `2 * DEFAULT_DEBOUNCE_MS`.
- Functional: A new `configs/risk.toml` ships with byte-perfect translation of `configs/risk.yaml`'s comments and values (hand-translated).
- Non-functional: Zero behaviour change at runtime — same `RiskConfig` struct shape.

## Architecture

- `RiskConfig::from_path` switches from `serde_yaml::from_str(&content)` to `toml::from_str(&content)`.
- The intermediate `RiskDocument` wrapper struct (containing `risk: RiskConfig`) stays — TOML expresses it as `[risk]` table; `serde` semantics unchanged.
- All `r#"yaml: ..."#` inline test fixtures in `risk/config.rs` and `risk/reload.rs` rewritten as raw TOML strings.
- `crates/waf-engine/src/risk/config.rs` doc comments `//! YAML schema for ...` → `//! TOML schema for ...`.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/config.rs` (parser swap + test fixtures + doc comments)
- Modify: `crates/waf-engine/src/risk/reload.rs` (test fixtures + doc comments)
- Create: `configs/risk.toml` (hand-translated from `configs/risk.yaml`)
- Delete: `configs/risk.yaml` (at the end of phase, after all tests green)
- Modify: `crates/waf-api/src/risk_api.rs` (defer to Phase 8 — flagged here so the API layer compiles via the still-present `serde_yaml::Value` path; admin GET/PUT temporarily reads/writes TOML in this phase by trivial swap of `read_yaml_opt`/`write_yaml`)

## Implementation Steps

1. **TDD red — rewrite tests:**
   - In `crates/waf-engine/src/risk/config.rs::tests`, convert every `serde_yaml::from_str(...)` and `r#"risk: ..."#` literal to TOML equivalents using `toml::from_str`. Examples:
     - YAML `risk:\n  enabled: true` → TOML `[risk]\nenabled = true`
     - YAML lists `paths: [a, b]` → TOML `paths = ["a", "b"]`
   - Add ONE Phase-1 equivalence test: `assert_yaml_toml_equivalent::<RiskDocument>(include_str!("../../../../configs/risk.yaml"), include_str!("../../../../configs/risk.toml"))` (the new TOML file doesn't exist yet → compile fail → expected red).
2. Confirm red: `cargo test -p waf-engine risk:: 2>&1 | tail`. Should see compile errors / test failures.
3. **Hand-write `configs/risk.toml`:** translate `configs/risk.yaml` line-by-line, preserving the comment blocks. Note TOML ordering rule: any scalar under `[risk]` must come BEFORE sub-tables `[risk.store]`, `[risk.decay]`, `[risk.seed]`, `[risk.canary]`. Comments stay grouped with their sub-table.
4. **Swap the parser:** `let doc: RiskDocument = toml::from_str(&content).context("risk: parse TOML")?;`. Update the error context string.
5. **Update `risk/reload.rs` tests:** rename `risk.yaml` → `risk.toml` in tempdir paths; switch fixture content to TOML; assert that ArcSwap reload still works.
6. **Update API layer (interim — finalised Phase 8):** in `waf-api/src/risk_api.rs`:
   - `read_yaml_opt` → `read_toml_opt` (`toml::from_str::<toml::Value>` then convert to `serde_json::Value` via the codec helper — placeholder fn from Phase 2).
   - `write_yaml` → `write_toml`.
   - `resolve_path(&state, "configs/risk.yaml")` → `configs/risk.toml`.
   - Comment header `Config source: configs/risk.yaml` → `configs/risk.toml`.
7. **Update `engine.rs` doc comments:** any `configs/risk.yaml` literal in doc comments → `.toml`.
8. **Delete `configs/risk.yaml`** once all tests green: `git rm configs/risk.yaml`.
9. **Test commands:**
   ```bash
   cargo check -p waf-engine -p waf-api
   cargo test -p waf-engine risk::
   cargo test -p waf-engine --test '*' risk
   cargo test -p waf-api risk
   cargo clippy --workspace -- -D warnings
   cargo fmt --all -- --check
   ```

## Todo List

- [ ] Unit tests rewritten with TOML fixtures (red)
- [ ] Equivalence test added (red until `configs/risk.toml` exists)
- [ ] `configs/risk.toml` hand-written with preserved comments
- [ ] `RiskConfig::from_path` swapped to `toml::from_str`
- [ ] `risk/reload.rs` test fixtures + path renamed
- [ ] `risk_api.rs` reads/writes TOML, path updated
- [ ] `engine.rs` doc references updated
- [ ] `configs/risk.yaml` deleted from repo
- [ ] All `risk::` tests green
- [ ] `cargo clippy --workspace -- -D warnings` clean

## Success Criteria

- [ ] `cargo test -p waf-engine risk::` green
- [ ] `cargo test -p waf-api risk` green (admin GET returns same JSON shape as before; PUT round-trips)
- [ ] Live load test: `cargo run -- -c configs/default.toml run` boots; `tail -f logs` shows `risk: hot-reload OK` after touching `configs/risk.toml`
- [ ] No `serde_yaml` references remain in `risk/`
- [ ] `git grep risk.yaml` returns only plan/changelog/historic-doc mentions

## Risk Assessment

- **Risk:** `serde(default)` defaults differ between YAML and TOML parsing paths (notably for `Option<T>` — YAML treats missing keys as `None`, so does TOML, but YAML's `~` / explicit null had been valid). **Mitigation:** Equivalence test from Phase 1 catches mismatch; rejecting unknown fields (Phase 2 audit) catches the inverse.
- **Risk:** Commented-out Redis block in `risk.yaml` uses YAML-specific indentation. Hand-translation must preserve as TOML-commented lines. **Mitigation:** Reviewer pass before merging this phase.
- **Risk:** `risk_api.rs` codec swap in step 6 uses Phase-2 placeholder helper; that helper is finalised in Phase 8. If FE behaviour breaks here, accept Phase 8 will fix structurally. **Mitigation:** Phase 3 test for `risk_api` is shallow — just verify GET returns valid JSON; deep FE round-trip is Phase 8's job.
