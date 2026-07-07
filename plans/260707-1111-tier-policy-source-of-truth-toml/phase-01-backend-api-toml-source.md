# Phase 1 — Backend: tier-policy API reads/writes `tier-protection.toml`

## Context

- `crates/waf-api/src/tier_policies_api.rs` — current YAML handlers (rewrite)
- `crates/waf-common/src/tier.rs` + `tier_match.rs` — `TierConfig`, tagged `CachePolicy { mode, ttl_seconds }`, `PathMatch/HostMatch { kind, value }`, `HttpMethod` (UPPERCASE)
- `crates/gateway/src/tiered/` — `TierSnapshot::try_from_config` (validate + regex compile), `TierClassifier::new/classify`, `RequestParts`, watcher `try_reload`
- `crates/waf-api/src/config_files.rs` — `resolve_path`, atomic `write_yaml_str` (pattern for TOML twin)
- Precedent: `panel_config_path` plumbing (`state.rs:61`, `main.rs:1246/1846`)

## Steps

1. **Cargo**: add `toml = { workspace = true }` to `crates/waf-api/Cargo.toml`.
2. **`config_files.rs`**: add `write_toml_str(path, contents)` — same mkdir + `<stem>.toml.tmp` + rename sequence as `write_yaml_str`.
3. **`state.rs`**: add `pub tier_config_path: Option<PathBuf>` (init `None` in `AppState::new`).
4. **`main.rs`**: after each `AppState` construction that has `config` in scope (mirror `panel_config_path` at :1846 and the :1031 site), set `tier_config_path = config.tiered_protection.config_path.clone().map(PathBuf::from)` — the *identical* value the watcher spawn uses (`main.rs:1441`), so API and engine provably share one file. CWD-relative, matching engine semantics.
5. **Rewrite `tier_policies_api.rs`**:
   - `#[derive(Serialize, Deserialize)] struct TierProtectionFile { tiered_protection: TierConfig }` (envelope; gateway's `TomlEnvelope` is private).
   - Path helper: `state.tier_config_path` else fallback `resolve_path(state, "configs/tier-protection.toml")`.
   - **GET**: read + `toml::from_str::<TierProtectionFile>`; missing file → built-in default (`default_tier: catch_all`, empty rules, 4× `TierPolicy::default()`); parse failure → 500 with cause (file exists but corrupt is an operator problem, not "use defaults"). Return `TierConfig` as JSON.
   - **PUT**: `serde_json::from_value::<TierConfig>(body)` → `TierSnapshot::try_from_config(cfg.clone())` (exact watcher-side validation incl. bad regex) → on error 400 with message, file untouched → else `toml::to_string_pretty(&TierProtectionFile { .. })` → `write_toml_str`. Watcher hot-reloads via rename event.
   - **dry-run**: body `{ method, path, host? }` → load current `TierConfig` from file → `TierClassifier::new(&rules, default_tier)` → `classify(RequestParts { host: lowercased or "", path, method, headers: &HeaderMap::new() })` → respond `{ matched_tier, policy }` (drop `matched_rule_id` — engine rules have no ids; FE updated in phase 2).
6. **Configs**: add to `configs/default.toml` + `configs/local-dev.toml` (copy full-features.toml:125-127 wording):
   ```toml
   [tiered_protection]
   config_path = "configs/tier-protection.toml"
   ```
7. **Delete** `configs/tier-policies.yaml` (`git rm`; its uncommitted diff dies with it). Grep-verify no remaining references outside plans/docs history.

## Tests (inline `mod tests`, reuse risk_api test harness style)

- Shipped `configs/tier-protection.toml` parses via envelope + builds snapshot (regression guard for panel writes).
- PUT valid engine JSON → written file loads through `gateway::tiered::try_reload` (watcher-equivalence proof).
- PUT invalid (thresholds out of order / missing tier / bad regex) → 400, file unchanged.
- GET with missing file → defaults; GET after PUT → round-trips.
- dry-run: prefix + regex + method rules classify identically to `TierClassifier` expectations; default-tier fallback.

## Verify

`cargo test -p waf-api` green; `cargo clippy -p waf-api` no new warnings.

## Risk / rollback

Pure additive plumbing + one module rewrite behind unchanged routes. Revert commit restores YAML flow.
