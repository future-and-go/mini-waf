---
phase: 8
title: "tier-policies & admin API switchover"
status: pending
effort: "1d"
priority: P1
dependencies: [3, 4, 5, 6, 7]
---

# Phase 8: tier-policies & admin API switchover

## Overview

Finalises the JSON↔TOML codec used by the six admin API endpoints (`risk_api`, `device_fp_api`, `challenge_api`, `relay_api`, `ddos_api`, `tier_policies_api`). Phase 3–7 used a Phase-2 placeholder; this phase replaces all six call-sites with a single shared `config_codec` module and gives it a property-test suite. Also migrates `configs/tier-policies.yaml` — the only file with no engine-side loader.

## Requirements

- Functional: New `crates/waf-api/src/config_codec.rs` provides:
  ```rust
  pub fn read_toml_value(path: &Path) -> ApiResult<Option<serde_json::Value>>;
  pub async fn write_toml_value(path: &Path, value: &serde_json::Value) -> ApiResult<()>;
  fn json_to_toml(j: &serde_json::Value) -> Result<toml::Value, CodecError>; // strips nulls
  fn toml_to_json(t: &toml::Value) -> serde_json::Value;
  ```
- Functional: All six admin endpoints use this module; no per-file YAML helpers remain.
- Functional: `configs/tier-policies.toml` ships, hand-translated.
- Non-functional: Property test (proptest, 1k cases) round-trips JSON → TOML → JSON → TOML and asserts stability after the first conversion (idempotent after null-stripping).

## Architecture

- **`json_to_toml`** strips:
  - `Value::Null` → key omitted from parent object
  - `Value::Null` in array → omitted (TOML doesn't allow nulls in arrays either — error if all elements null)
  - Numeric: `i64`/`u64`/`f64` preserved; `Value::Number` precision >`i64::MAX` → `Err(CodecError::IntOverflow)`
- **`toml_to_json`** straight-line (TOML datetimes serialise as JSON strings — acceptable since FE has never sent datetimes).
- TOML's table-key ordering rule satisfied by `toml::Value::Table(BTreeMap)` (sorted) — `toml::to_string` does the right thing.

## Related Code Files

- Create: `crates/waf-api/src/config_codec.rs`
- Create: `crates/waf-api/tests/config_codec_property.rs`
- Modify: `crates/waf-api/src/lib.rs` (re-export `config_codec`)
- Modify: `crates/waf-api/src/risk_api.rs` (delete inline `read_yaml_opt`/`write_yaml`; use `config_codec`)
- Modify: `crates/waf-api/src/device_fp_api.rs` (same)
- Modify: `crates/waf-api/src/challenge_api.rs` (same)
- Modify: `crates/waf-api/src/relay_api.rs` (same)
- Modify: `crates/waf-api/src/ddos_api.rs` (same)
- Modify: `crates/waf-api/src/tier_policies_api.rs` (codec + path)
- Modify: `crates/waf-api/Cargo.toml` (add `proptest` to dev-deps if not present; `toml` to deps)
- Create: `configs/tier-policies.toml`
- Delete: `configs/tier-policies.yaml`

## Implementation Steps

1. **TDD red — property test FIRST:**
   ```rust
   proptest! {
       #[test]
       fn json_toml_roundtrip_idempotent(v in arbitrary_json_value()) {
           let toml_v = json_to_toml(&v).map_err(|_| TestCaseError::reject("bad input"))?;
           let json_back = toml_to_json(&toml_v);
           let toml_again = json_to_toml(&json_back).unwrap();
           assert_eq!(toml_v, toml_again);
       }
   }
   ```
   Strategy `arbitrary_json_value` (depth ≤ 4, no nulls inside arrays, keys are TOML-legal). Initially red because `config_codec` doesn't exist.
2. **Implement `config_codec.rs`:**
   - `json_to_toml`: recursive walk. Object → `toml::map::Map`. Array → `toml::Value::Array` (error on null elements). Number → preserve via `toml::Value::Integer(i64)` or `Float(f64)`. String/bool direct.
   - `toml_to_json`: recursive walk.
   - `read_toml_value`/`write_toml_value`: async fs read + `toml::from_str::<toml::Value>` then `toml_to_json`.
   - `write_toml_value`: `json_to_toml` → `toml::to_string_pretty` → atomic write.
3. Run property test green.
4. **Refactor each of the 6 endpoint modules:** delete inline yaml helpers, import `config_codec`. Endpoints' `yaml_to_fe`/`fe_to_yaml` mapping logic stays unchanged (operates on `serde_json::Value`); only the read/write layer swaps.
5. **Hand-write `configs/tier-policies.toml`:**
   ```toml
   classifier_rules = []

   [policies.catch_all]
   cache_policy = "aggressive"
   ddos_threshold_rps = 1000
   fail_mode = "open"

   [policies.catch_all.risk_thresholds]
   allow = 20
   block = 85
   challenge = 60

   [policies.critical]
   # ... etc
   ```
6. **Update `tier_policies_api.rs`** to use `config_codec` and the new `configs/tier-policies.toml` path.
7. **Delete `configs/tier-policies.yaml`.**
8. **Test commands:**
   ```bash
   cargo test -p waf-api config_codec
   cargo test -p waf-api tier_policies
   cargo test -p waf-api risk device_fp challenge relay ddos
   cargo clippy --workspace -- -D warnings
   ```

## Todo List

- [ ] Property test red before impl
- [ ] `config_codec::json_to_toml` strips nulls correctly
- [ ] `config_codec::toml_to_json` lossless on supported subset
- [ ] All 6 admin endpoints use `config_codec`
- [ ] `configs/tier-policies.toml` hand-written
- [ ] `configs/tier-policies.yaml` deleted
- [ ] Property test (1k cases) green
- [ ] All 6 endpoint tests green
- [ ] Workspace clippy + fmt clean

## Success Criteria

- [ ] `cargo test -p waf-api` green
- [ ] Property test 1k cases pass
- [ ] FE round-trip: `curl GET /api/risk/config` → same JSON shape as before migration; `curl PUT` → file on disk matches expected TOML; reload picks up change
- [ ] No `serde_yaml` imports remain in any of the 6 endpoint files

## Risk Assessment

- **Risk:** TOML integers are i64-only; FE may send numbers larger than i64::MAX (unlikely for config knobs, but possible). **Mitigation:** `json_to_toml` returns `CodecError::IntOverflow`; endpoint returns 400 with clear message.
- **Risk:** FE sends `null` to mean "unset"; codec drops the key, but the FE-side mapping (`yaml_to_fe`) expected a key → default fallback. **Mitigation:** Re-verify each `*_to_fe` helper handles missing keys (current code uses `.get().unwrap_or(default)` everywhere → safe). Document in phase report.
- **Risk:** `toml::to_string_pretty` reorders keys alphabetically; FE-edited files may look diff-noisy compared to operator's hand-edited TOML. **Mitigation:** Accept the noise (FE-driven writes are expected to canonicalise). Document.
- **Risk:** `tier-policies.toml` keys (cache_policy, fail_mode) are enums in upstream Rust deser path. Bad string → tier_policies endpoint or engine refuses. **Mitigation:** Existing validation untouched; equivalence test against `configs/tier-policies.yaml` proves identical struct deser.

## Unresolved questions

- Should `config_codec` preserve insertion order of FE-sent JSON keys (via `IndexMap`) rather than alphabetising? **Decision:** No — TOML's `to_string_pretty` is deterministic alphabetic; deterministic > FE-driven. Flag if FE complains.
