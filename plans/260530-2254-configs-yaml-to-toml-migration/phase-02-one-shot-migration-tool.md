---
phase: 2
title: "One-shot migration tool"
status: pending
effort: "1d"
priority: P1
dependencies: [1]
---

# Phase 2: One-shot migration tool

## Overview

Ship a `waf migrate-configs` CLI subcommand operators run once per deployment to convert their existing `configs/*.yaml` to `configs/*.toml`. Hand-translated comments live in the shipped repo defaults, but operators may have customised values — the tool must preserve those values losslessly. Comments in customised user files are **best-effort** (will be replaced by a banner pointing to the shipped defaults), since `serde_yaml` → struct → `toml` round-trip drops them. This is acceptable per the cutover plan.

## Requirements

- Functional: `waf migrate-configs --dir configs/` reads every `*.yaml`, writes `*.toml` adjacent, leaves the `.yaml` in place (operator deletes manually after verifying).
- Functional: `--in-place` flag deletes the YAML after successful write (atomic rename via `.tmp`).
- Functional: Refuses to overwrite an existing `.toml` unless `--force`.
- Functional: For each of the 8 known config files, deserialises into its **typed** struct (not generic Value) so unknown fields are rejected loudly — protects against silent data loss for unrecognised customisations.
- Non-functional: Tool exits non-zero with the failing file path on any error; never partial-writes.

## Architecture

- New module `crates/prx-waf/src/commands/migrate_configs.rs`.
- Wired into `crates/prx-waf/src/main.rs` clap command tree alongside `migrate`, `seed-admin`, `run`.
- Per-file dispatch table:
  ```rust
  const KNOWN: &[(&str, fn(&str) -> Result<String>)] = &[
      ("risk.yaml",          convert::<RiskDocument>),
      ("device-fp.yaml",     convert::<DeviceFpDocument>),
      ("challenge.yaml",     convert::<ChallengeDocument>),
      ("relay.yaml",         convert::<RelayDocument>),
      ("rate-limit.yaml",    convert::<RateLimitDocument>),
      ("tx-velocity.yaml",   convert::<TxVelocityDocument>),
      ("ddos.yaml",          convert::<DdosDocument>),
      ("tier-policies.yaml", convert_generic),  // no engine struct — generic Value
  ];
  fn convert<T: DeserializeOwned + Serialize>(yaml: &str) -> Result<String> {
      let doc: T = serde_yaml::from_str(yaml).context("yaml parse")?;
      toml::to_string_pretty(&doc).context("toml serialise").map_err(Into::into)
  }
  ```
- `convert_generic` for `tier-policies` uses `serde_yaml::Value → toml::Value` via the codec helper from Phase 8 (forward-declared here, finalised in Phase 8).

## Related Code Files

- Create: `crates/prx-waf/src/commands/mod.rs` (if not present — add `pub mod migrate_configs;`)
- Create: `crates/prx-waf/src/commands/migrate_configs.rs`
- Create: `crates/prx-waf/tests/migrate_configs_e2e.rs`
- Modify: `crates/prx-waf/src/main.rs` (add clap subcommand)
- Modify: `crates/prx-waf/Cargo.toml` (add `serde_yaml` to dev/binary deps if not already; reuse `waf-engine` re-exports for typed structs)

## Implementation Steps

1. **TDD red:** Write `tests/migrate_configs_e2e.rs` with one test per known file. Each test fixtures a tempdir with the **current** YAML content (copy-pasted from `configs/<name>.yaml`), runs the converter, and asserts the resulting TOML re-parses into a struct equal to the YAML's struct. Initially red because the binary doesn't exist.
2. **Wire clap subcommand:** Add `MigrateConfigs { dir: PathBuf, in_place: bool, force: bool }` to the `Commands` enum in `main.rs`.
3. **Implement `commands/migrate_configs.rs`:**
   - Walk the dispatch table.
   - For each file: read → typed convert → atomic write to `<name>.toml.tmp` → fsync → rename → optionally delete `.yaml`.
   - Log `converted: <path>` per file; final `summary: N converted, M skipped, K errors`.
4. **Integrate the typed structs:** Some current docs (`RiskDocument`, `DeviceFpDocument`, …) are `pub(crate)` inside their modules. Either (a) bump visibility to `pub` with a `#[doc(hidden)]` marker, or (b) add a thin `pub fn convert_yaml_to_toml(name: &str, yaml: &str) -> Result<String>` on each module's public surface. Pick (b) — narrower API.
5. **Re-export from each waf-engine module:** `pub use config::convert_yaml_to_toml as <module>_convert;` in `risk/mod.rs`, `device_fp/mod.rs`, `challenge/mod.rs`, `relay/mod.rs`, `checks/ddos/mod.rs`, `checks/rate_limit/mod.rs`, `checks/tx_velocity/mod.rs`.
6. **Generic path for tier-policies:** placeholder using `serde_yaml::from_str::<serde_yaml::Value>` → manual recursive walk that converts to `toml::Value` (strip nulls, sort table keys to satisfy TOML ordering). Finalised + reused in Phase 8.
7. **Atomic write helper:** `write_atomic(path, contents)` → `<path>.tmp` → `fsync` → `rename(path)`. Pull out as private fn.
8. **Run tests green:** `cargo test -p prx-waf --test migrate_configs_e2e`.
9. **CLI smoke:** `cargo run -- migrate-configs --dir /tmp/copy-of-configs`. Verify output files round-trip via Phase 1's `assert_yaml_toml_equivalent` helper.
10. **Format + clippy:** `cargo fmt --all && cargo clippy --workspace -- -D warnings`.

## Todo List

- [ ] Tests red before impl
- [ ] Clap subcommand `migrate-configs` registered
- [ ] Dispatch table covers all 8 files
- [ ] Atomic write (`.tmp` + fsync + rename)
- [ ] `--force` / `--in-place` flags both have test coverage
- [ ] Per-module `convert_yaml_to_toml` public fn exposed
- [ ] Generic `tier-policies` path scaffolded (full impl finalised Phase 8)
- [ ] Tests green
- [ ] `cargo clippy -- -D warnings` clean

## Success Criteria

- [ ] `cargo test -p prx-waf --test migrate_configs_e2e` green (8 conversion tests)
- [ ] Manual run on the live `configs/` produces 8 `.toml` files that match Phase 3–7's hand-written defaults at struct-equality level
- [ ] Tool refuses to clobber unless `--force`
- [ ] Tool is idempotent (re-running with `--force` produces byte-identical output)
- [ ] Documented in `--help` output

## Risk Assessment

- **Risk:** Unknown YAML keys silently dropped by `serde_yaml::from_str::<TypedStruct>`. The current structs use `#[serde(deny_unknown_fields)]` inconsistently. **Mitigation:** Audit each Document struct; add `deny_unknown_fields` where missing as part of this phase. Audit log of which structs are updated goes in phase report.
- **Risk:** `toml::to_string_pretty` may emit ordering that the runtime parser rejects (table-after-scalar rule). **Mitigation:** All `toml` crate output respects that rule; tests catch any violation immediately.
- **Risk:** Comments lost. **Mitigation:** Documented behaviour. Tool emits a banner comment at the top of each output: `# Auto-generated from <name>.yaml by 'waf migrate-configs'. See https://… for the upstream commented default.`

## Unresolved questions

- Should `migrate-configs` ALSO update `configs/default.toml`'s `rate_limit.config_path = "configs/rate-limit.yaml"` line? **Recommendation:** No — that's a `default.toml` edit by `sed` or by hand; auto-editing it risks clobbering operator customisations. Documented in Phase 9.
