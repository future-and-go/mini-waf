---
phase: 1
title: "Foundation & deps"
status: pending
effort: "0.5d"
priority: P1
dependencies: []
---

# Phase 1: Foundation & deps

## Overview

Add the `toml` crate to `waf-engine`'s `Cargo.toml` (already present at workspace root as `toml = "1.1"`), capture a green baseline (`cargo check --workspace`, `cargo test --workspace`), and stand up a tiny shared test util that asserts a `configs/<name>.toml` on disk parses identically to its still-present `configs/<name>.yaml` counterpart. That util is the safety net used by Phases 3–7: each phase only deletes the YAML once the equivalence check holds for the new TOML.

## Requirements

- Functional: `cargo check --workspace` + `cargo test --workspace` are green BEFORE and AFTER this phase (no behaviour change).
- Functional: A new test helper `tests/common/yaml_toml_equivalence.rs` (under `waf-engine/tests/`) provides `assert_yaml_toml_equivalent::<T: DeserializeOwned + PartialEq>(yaml_path, toml_path)`.
- Non-functional: Zero clippy warnings (project enforces `-D warnings`).

## Architecture

- `crates/waf-engine/Cargo.toml` gains `toml = { workspace = true }`.
- `crates/waf-engine/tests/common/mod.rs` re-exports `yaml_toml_equivalence`.
- The helper deserialises both files into the same typed struct `T` and asserts `==`. (Pure file-on-disk comparison would fail because of formatting/comments; struct equality is the true semantic.)

## Related Code Files

- Create: `crates/waf-engine/tests/common/mod.rs`
- Create: `crates/waf-engine/tests/common/yaml_toml_equivalence.rs`
- Modify: `crates/waf-engine/Cargo.toml` (add `toml = { workspace = true }` under `[dependencies]`; `serde_yaml` stays — removed in Phase 10)

## Implementation Steps

1. Run baseline: `cargo check --workspace && cargo test --workspace 2>&1 | tail -40`. Record the exact pass/fail count in your phase notes. Any failing test = STOP, fix or document before proceeding.
2. Add `toml = { workspace = true }` to `crates/waf-engine/Cargo.toml` `[dependencies]`. Sort the block.
3. Create `crates/waf-engine/tests/common/mod.rs` with `pub mod yaml_toml_equivalence;`.
4. Implement the helper:
   ```rust
   pub fn assert_yaml_toml_equivalent<T>(yaml: &str, toml_str: &str)
   where T: serde::de::DeserializeOwned + PartialEq + std::fmt::Debug {
       let from_yaml: T = serde_yaml::from_str(yaml).expect("yaml parses");
       let from_toml: T = toml::from_str(toml_str).expect("toml parses");
       assert_eq!(from_yaml, from_toml, "yaml/toml deser must agree");
   }
   ```
5. Add a smoke test in `crates/waf-engine/tests/common/yaml_toml_equivalence.rs` that round-trips a trivial `#[derive(Deserialize, PartialEq, Debug)]` struct.
6. `cargo check -p waf-engine` then `cargo test -p waf-engine --test common -- --nocapture`.
7. `cargo clippy --workspace -- -D warnings && cargo fmt --all -- --check`.

## Todo List

- [ ] Baseline `cargo test --workspace` is green; record counts
- [ ] `toml = { workspace = true }` added to `crates/waf-engine/Cargo.toml`
- [ ] `tests/common/yaml_toml_equivalence.rs` helper compiles + smoke test passes
- [ ] `cargo clippy --workspace -- -D warnings` green
- [ ] `cargo fmt --all -- --check` clean

## Success Criteria

- [ ] `cargo check --workspace` green
- [ ] `cargo test --workspace` green (no regression vs baseline)
- [ ] New helper used by at least one smoke test in this phase
- [ ] No new `unwrap()`/`expect()` in production code (only test helpers may `expect()`)

## Risk Assessment

- **Risk:** `toml` crate version skew. The workspace pin is `1.1`; check that the deser path used here (`toml::from_str`) is stable. **Mitigation:** Smoke-test in step 5 catches API mismatch immediately.
- **Risk:** test helper accidentally compares struct defaults instead of parsed values. **Mitigation:** Smoke test uses a non-default value.
