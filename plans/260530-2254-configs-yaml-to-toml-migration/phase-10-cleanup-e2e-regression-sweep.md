---
phase: 10
title: "Cleanup & e2e regression sweep"
status: pending
effort: "0.75d"
priority: P1
dependencies: [1, 2, 3, 4, 5, 6, 7, 8, 9]
---

# Phase 10: Cleanup & e2e regression sweep

## Overview

Drop `serde_yaml` from `waf-engine`'s config loading path (NOT from rule loaders), drop from `waf-api`'s six migrated endpoints (NOT from rules / access-lists / geo), run the full e2e cluster test, run the nightly suite, gate the release.

## Requirements

- Functional: `serde_yaml` removed from `crates/waf-engine/Cargo.toml` **only if** no remaining usages outside `rules/formats/{yaml,custom_rule_yaml}.rs`, `bin/migrate-yaml-rules.rs`, `checks/owasp.rs`. Audit decides.
- Functional: `serde_yaml` removed from `crates/waf-api/Cargo.toml` **only if** no remaining usages outside `rules_api.rs`, `access_lists_api.rs`, `geo_api.rs`. Audit decides.
- Functional: `tests/e2e-cluster.sh` runs end-to-end green.
- Functional: `.github/workflows/nightly-e2e.yml` matrix passes (or pre-merge dry-run via `act`).

## Architecture

- Audit step is mechanical: `grep -rn serde_yaml crates/waf-engine/src/ crates/waf-api/src/` and bucket each hit into IN-SCOPE-REMOVE vs OUT-OF-SCOPE-KEEP.
- If a crate retains ANY `serde_yaml` usage, the Cargo.toml dep stays.

## Related Code Files

- Audit: `crates/waf-engine/Cargo.toml`, `crates/waf-api/Cargo.toml`
- Audit: `crates/waf-engine/src/**/*.rs`, `crates/waf-api/src/**/*.rs`
- Modify (conditional): Cargo.toml dep lists per audit outcome
- Modify: `crates/waf-engine/src/relay/reload.rs` and any other modules' doc comments still saying "YAML" — final sweep
- Verify: `Cargo.lock` updates cleanly after dep changes
- Verify: `tests/e2e-cluster.sh` exit 0

## Implementation Steps

1. **Audit:**
   ```bash
   grep -rn 'use serde_yaml\|serde_yaml::' crates/waf-engine/src/ crates/waf-api/src/
   ```
   Expected remaining hits (out-of-scope, KEEP):
   - `waf-engine/src/rules/formats/yaml.rs`
   - `waf-engine/src/rules/formats/custom_rule_yaml.rs`
   - `waf-engine/src/checks/owasp.rs`
   - `waf-engine/src/bin/migrate-yaml-rules.rs`
   - `waf-api/src/rules_api.rs`
   - `waf-api/src/access_lists_api.rs`
   - `waf-api/src/geo_api.rs`
   - `waf-engine/src/rules/formats/mod.rs` (if it still uses `serde_yaml::to_string` for YAML rule export)
   Anything else = leftover, must be removed.
2. **Remove leftovers** if any.
3. **Cargo.toml decision:**
   - Both crates retain serde_yaml deps (rule formats still need it). The cleanup is **code-side only**, not dep-side. Document this in phase report.
4. **Doc-comment sweep:** `git grep -nE 'YAML|yaml' crates/waf-engine/src/{risk,device_fp,challenge,relay}/ crates/waf-engine/src/checks/{ddos,rate_limit,tx_velocity}/` — any doc comment still saying "YAML schema" or "parsing YAML" → fix to "TOML".
5. **Run unit + integration suite:**
   ```bash
   cargo test --workspace --all-features 2>&1 | tee /tmp/cargo-test-final.log
   ```
6. **Run E2E cluster suite:**
   ```bash
   ./tests/e2e-cluster.sh 2>&1 | tee /tmp/e2e-cluster.log
   ```
   Inspect `tests/artifacts/` for JUnit/HTML reports.
7. **Run nightly-equivalent workflow dry-run:** if `act` available, `act -W .github/workflows/nightly-e2e.yml`; else trigger via PR.
8. **Final pre-push checks:**
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-features -- -D warnings
   cargo check --workspace --all-features
   ```
9. **Manual hot-reload smoke (the regression most likely to slip):**
   ```bash
   cargo run -- -c configs/default.toml run &
   sleep 5
   # touch each migrated file, watch logs for "hot-reload OK"
   for f in risk device-fp challenge relay rate-limit tx-velocity ddos; do
     touch configs/$f.toml
     sleep 1
   done
   kill %1
   ```

## Todo List

- [ ] `serde_yaml` audit complete; in-scope removals applied
- [ ] Doc-comment sweep removes all stale "YAML" mentions in migrated modules
- [ ] `cargo test --workspace --all-features` green
- [ ] `./tests/e2e-cluster.sh` exit 0
- [ ] Nightly workflow dry-run green
- [ ] Hot-reload smoke confirms 7 modules reload (all except tier-policies which has no engine watcher)
- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --workspace --all-features -- -D warnings` clean
- [ ] Phase report records final audit table

## Success Criteria

- [ ] `git grep -nE 'configs/[a-z-]+\.ya?ml' -- ':!plans/' ':!CHANGELOG.md'` returns ZERO
- [ ] All test suites green (`cargo test --workspace --all-features` + `e2e-cluster.sh`)
- [ ] Hot-reload working for all 7 engine-watched configs
- [ ] No `serde_yaml::` imports remain in migrated config loaders or migrated endpoints
- [ ] CHANGELOG entry is accurate (operators have unambiguous upgrade steps)

## Risk Assessment

- **Risk:** Hidden serde_yaml dep via transitive crate (unlikely — `serde_yaml` is direct). **Mitigation:** `cargo tree -p waf-engine -i serde_yaml` confirms direct-only.
- **Risk:** Nightly e2e workflow exposes a config-path mismatch missed in Phase 9. **Mitigation:** Dry-run before merging; if positive, fix forward.
- **Risk:** Hot-reload watcher continues to fire on the (now-deleted) `.yaml` file path — would be a Phase 1–7 bug; this phase is the catch-net. **Mitigation:** Smoke step 9 above. If any watcher path is stale, return to the originating phase, fix, re-run.
- **Risk:** `cargo bench` baselines may shift because `serde_yaml` removal speeds up cold-start. **Mitigation:** Benchmarks are not part of the cutover gate; note any meaningful shift in CHANGELOG.

## Unresolved questions

- Should `tests/e2e/configs/e2e.toml` be re-audited for `.yaml` refs? **Recommendation:** Yes — include in step 1 audit. The e2e suite mounts its own config; if it references migrated `.yaml` files (it shouldn't), Phase 10 fixes them.
- Should we delete `crates/waf-engine/src/bin/migrate-yaml-rules.rs`? **Recommendation:** No — separate concern (rules YAML), out of scope.
