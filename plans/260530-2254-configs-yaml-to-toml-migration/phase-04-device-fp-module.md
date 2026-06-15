---
phase: 4
title: "device-fp module"
status: pending
effort: "1d"
priority: P1
dependencies: [3]
---

# Phase 4: device-fp module

## Overview

Most complex schema: top-level enabled flag + nested `[device_fp.capture.tls]`, `[device_fp.capture.h2]`, `[device_fp.store]`, an array-of-tables `[[device_fp.providers]]` with per-provider optional fields, and a nested `[device_fp.behavior.*]` sub-config. This phase validates that the TOML representation of array-of-tables matches the existing `Vec<ProviderConfig>` deserialisation. Same TDD discipline as Phase 3.

## Requirements

- Functional: `DeviceFpConfig::from_path` reads TOML, same struct shape.
- Functional: `[[device_fp.providers]]` array-of-tables deserialises identically to the previous YAML `providers:` sequence.
- Functional: `[device_fp.behavior]` block stays optional (omit → `BehaviorConfig::default()`).
- Functional: `configs/device-fp.toml` ships, hand-translated with comments.

## Architecture

- `crates/waf-engine/src/device_fp/config.rs::from_path` swaps `serde_yaml::from_str` → `toml::from_str`.
- The `behavior/config.rs` sub-module needs no changes (it deserialises a subset of the parent's Value tree; toml carries it through unchanged).
- TOML array-of-tables uses `[[device_fp.providers]]` repeated. Per-provider keys vary; current struct (`device_fp/config.rs:172`) is **single struct with Option<>** fields, not enum-tagged, so any provider table writes all its keys flat:
  ```toml
  [[device_fp.providers]]
  name = "ip_hopping"
  window_secs = 600
  max_distinct_ips = 3
  signal_weight = 25
  ```
- `device_fp_api.rs` admin endpoint switches to TOML codec (same pattern as `risk_api.rs` in Phase 3).

## Related Code Files

- Modify: `crates/waf-engine/src/device_fp/config.rs` (parser, doc comments, tests)
- Modify: `crates/waf-engine/src/device_fp/reload.rs` (test fixtures, path)
- Modify: `crates/waf-engine/src/device_fp/mod.rs` (`p.join("device-fp.yaml")` test refs)
- Modify: `crates/waf-engine/src/device_fp/behavior/config.rs` (doc comments)
- Modify: `crates/waf-api/src/device_fp_api.rs` (codec swap, path)
- Create: `configs/device-fp.toml`
- Delete: `configs/device-fp.yaml`

## Implementation Steps

1. **TDD red:** Convert all inline YAML fixtures in `device_fp/config.rs::tests`, `device_fp/reload.rs::tests`, `device_fp/mod.rs::tests` to TOML. Critical conversions:
   - YAML `algorithms: [ja3, ja4]` → TOML `algorithms = ["ja3", "ja4"]`
   - YAML `exempt_paths: ["/", "/login"]` → TOML `exempt_paths = ["/", "/login"]`
   - YAML providers sequence → TOML `[[device_fp.providers]]` blocks (one per provider entry)
2. Add equivalence test: `assert_yaml_toml_equivalent::<DeviceFpDocument>(include_str!("../../../../configs/device-fp.yaml"), include_str!("../../../../configs/device-fp.toml"))`.
3. Confirm red: `cargo test -p waf-engine device_fp::`.
4. **Hand-write `configs/device-fp.toml`** — special attention to:
   - TOML doesn't allow keys after a sub-table in the same parent table → place all `[device_fp]` scalars before `[device_fp.capture]`, `[device_fp.store]`, `[[device_fp.providers]]`, `[device_fp.behavior]`.
   - `behavior.exempt_paths` / `exempt_prefixes` are inline arrays — keep them inline.
5. **Swap parser:** `let doc: DeviceFpDocument = toml::from_str(s).context("device_fp: parse TOML")?;`.
6. **Update `device_fp_api.rs`:**
   - `read_yaml_opt` → `read_toml_opt` (codec helper).
   - `write_yaml` → `write_toml`.
   - `configs/device-fp.yaml` → `.toml` in two `resolve_path` call sites.
   - Update module doc header.
7. **Update the `include_str!` path for the live-config test in `config.rs:341`:** `../../configs/device-fp.yaml` → `.toml`.
8. **Delete `configs/device-fp.yaml`.**
9. **Test commands:**
   ```bash
   cargo test -p waf-engine device_fp::
   cargo test -p waf-engine --test '*' device_fp
   cargo test -p waf-engine --test '*' behavior
   cargo test -p waf-api device_fp
   cargo clippy --workspace -- -D warnings
   ```

## Todo List

- [ ] Unit tests rewritten with TOML (red)
- [ ] Equivalence test added
- [ ] `configs/device-fp.toml` hand-written; ordering rule honoured
- [ ] Parser swap
- [ ] `device_fp_api.rs` codec + path swap
- [ ] `device_fp/mod.rs` test path + `include_str!` updated
- [ ] `configs/device-fp.yaml` deleted
- [ ] All `device_fp::`, `behavior::` tests green
- [ ] `cargo clippy --workspace -- -D warnings` clean

## Success Criteria

- [ ] `cargo test -p waf-engine device_fp::` green
- [ ] Acceptance + property tests `behavior_acceptance`, `behavior_property` green
- [ ] `cargo bench --bench device_fp_pipeline` runs unchanged (no API drift)
- [ ] Admin GET `/api/device-fp/config` returns same JSON shape

## Risk Assessment

- **Risk:** `[[device_fp.providers]]` table-array order vs YAML sequence order. **Mitigation:** `Vec<ProviderConfig>` deserialisation preserves order in both formats; equivalence test catches.
- **Risk:** `deny_unknown_fields` on `ProviderConfig` would reject TOML's pretty-printed serialisation if any new optional field is added. **Mitigation:** Verify the struct does NOT use `deny_unknown_fields` (it currently doesn't); document tradeoff in phase report.
- **Risk:** behavior sub-config's `Default` derives produce subtly different defaults than YAML's "omitted block". **Mitigation:** Round-trip test loads `configs/device-fp.toml` with `[device_fp.behavior]` omitted → asserts `cfg.behavior == BehaviorConfig::default()`.
