# Phase 02 — Directory Loader + Engine Wiring

**Status:** done  **Priority:** P2  **Effort:** 0.3d  **ACs:** 1, 2, 5

## Context Links

- Phase 01 parser: `crates/waf-engine/src/rules/formats/custom_rule_yaml.rs`
- Engine entry point: `crates/waf-engine/src/engine.rs::reload_rules`
- Rules dir convention: `RulesConfig.dir` (typically `./rules/`)

## Overview

Add a directory loader that scans `<rules_dir>/custom/*.yaml`, parses each file via Phase 01's `custom_rule_yaml::parse`, groups results by `host_code`, and feeds them into `CustomRulesEngine` via `load_host` (or `add_rule` per entry — see decision below). Hook into `WafEngine::reload_rules` so file rules load alongside DB rules at startup.

## Key Insights

- Existing DB load uses `load_host(host_code, rules)` which **replaces** the bucket. Combining file + DB into one bucket requires merging before the call. Easier: call `add_rule` per file rule **after** DB load completes — appends, sorts by priority. Slight cost: one sort per added rule. Acceptable for typical file rule counts (<100).
- Result: file rules and DB rules coexist in the same per-host bucket, evaluated in priority order.

## Requirements

1. New module: `crates/waf-engine/src/rules/custom_file_loader.rs`.
2. Public function:
   ```rust
   pub fn load_dir(dir: &Path) -> anyhow::Result<Vec<CustomRule>>;
   ```
   Returns all parsed rules (flat) from `<dir>/custom/*.yaml` (ignores subdirectories — `fr003-samples/` excluded).
3. On parse error for a single file: `warn!(file, error)` and continue. Never aborts overall load.
4. `WafEngine::reload_rules` calls `load_dir(&self.rules_dir)` after DB load and feeds rules into the engine via `add_rule`.
5. `WafEngine` holds `rules_dir: PathBuf` (passed in via config or defaulted to `./rules`). Add field if not present.

## Architecture

```
crates/waf-engine/src/rules/
├── engine.rs                    # unchanged
├── custom_file_loader.rs        # NEW
├── formats/
│   └── custom_rule_yaml.rs      # phase 01
└── ...
```

Pseudocode for `load_dir`:

```rust
pub fn load_dir(rules_root: &Path) -> Result<Vec<CustomRule>> {
    let custom_dir = rules_root.join("custom");
    if !custom_dir.is_dir() { return Ok(Vec::new()); }

    let mut out = Vec::new();
    for entry in std::fs::read_dir(&custom_dir)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() { continue; }
        if path.extension().and_then(|s| s.to_str()) != Some("yaml") { continue; }

        let content = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => { warn!(file = %path.display(), err = %e, "read failed"); continue; }
        };
        match custom_rule_yaml::parse(&content) {
            Ok(rules) => out.extend(rules),
            Err(e) => warn!(file = %path.display(), err = %e, "parse failed"),
        }
    }
    Ok(out)
}
```

Wiring in `engine.rs::reload_rules`, after DB load block:

```rust
// File-based custom rules (FR-003 yaml loader)
match crate::rules::custom_file_loader::load_dir(&self.rules_dir) {
    Ok(file_rules) => {
        let count = file_rules.len();
        for rule in file_rules {
            self.custom_rules.add_rule(rule);
        }
        info!("Loaded {count} file-based custom rules from {:?}", self.rules_dir);
    }
    Err(e) => warn!("Custom rule file load failed: {e}"),
}
```

### Reload Semantics

`reload_rules` is called on startup AND on admin-triggered reload. To avoid stale duplicates from prior load:

- Add `CustomRulesEngine::clear_file_rules(&self)` that removes all rules with a `source: RuleSource` flag set to `File`. Requires adding a `source` field to `CustomRule` (default `Db`).
- OR simpler: track file-rule IDs in a side set inside `CustomRulesEngine`; remove by ID before re-adding.
- **Chosen:** add `pub source: RuleSource { Db, File }` enum to `CustomRule` (default `Db` for back-compat). Engine gains `clear_file_rules()` that retains only `Db` entries.

## Related Code Files

**Create:**
- `crates/waf-engine/src/rules/custom_file_loader.rs`

**Modify:**
- `crates/waf-engine/src/rules/mod.rs` — `pub mod custom_file_loader;`
- `crates/waf-engine/src/rules/engine.rs` — add `RuleSource` enum + field on `CustomRule`; add `clear_file_rules` method
- `crates/waf-engine/src/engine.rs` — add `rules_dir: PathBuf` field; call loader in `reload_rules`

## Implementation Steps

1. Add `RuleSource` enum + `source` field on `CustomRule` (default `Db` via `#[serde(default)]` or builder default).
2. Update `from_db_rule` to set `source: RuleSource::Db`.
3. Update Phase 01 parser to set `source: RuleSource::File`.
4. Implement `CustomRulesEngine::clear_file_rules()`:
   ```rust
   pub fn clear_file_rules(&self) {
       for mut entry in self.rules.iter_mut() {
           entry.value_mut().retain(|e| !matches!(e.raw.source, RuleSource::File));
       }
   }
   ```
5. Implement `custom_file_loader::load_dir`.
6. Add `rules_dir` field to `WafEngine`; thread through constructor.
7. Wire in `reload_rules`: call `clear_file_rules()` then load + `add_rule` per file rule.
8. Tests: integration test in `tests/` with a tempdir + sample yaml file.
9. `cargo test -p waf-engine` + `cargo clippy` clean.

## Todo

- [~] `RuleSource` enum + field — dropped per revised plan (DB `load_host` already replaces buckets)
- [~] `clear_file_rules` method — dropped per revised plan
- [x] `custom_file_loader::load_dir`
- [x] Wire into `reload_rules`
- [x] `WafEngine.rules_dir` field (set-once via `set_rules_dir`, defaults to `./rules`)
- [x] Integration test (`tests/custom_rule_file_load.rs`) — AC-1, AC-2, AC-5
- [~] Update existing engine tests for new `source` field default — N/A (field dropped)

## Success Criteria

- AC-1: A `tempdir/custom/foo.yaml` with `kind: custom_rule_v1` produces a rule that matches a request via `WafEngine::check_request` (or whatever the engine entry is).
- AC-2: Existing `rules/custom/example.yaml` (no `kind`) is read but produces zero rules; no warnings logged.
- AC-5: Two files, one with `host_code: "*"` and one with `host_code: "myapp"` — both routes evaluated correctly.
- All existing engine tests pass with new `source` field.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Adding `source` field breaks existing `CustomRule` constructors in tests | Use `#[derive(Default)]` on `RuleSource` (default `Db`); use struct update syntax `..Default::default()` where helpful. May require touching multiple test fixtures — bounded effort |
| Reload ordering: file load runs before DB clear → orphaned file rules in old DB-only buckets | `clear_file_rules` runs first inside `reload_rules` at file-load step; DB load runs separately and uses `load_host` (replaces bucket entirely — wipes any prior file rules in that host). Order matters: DB load FIRST, then `clear_file_rules` is unnecessary because DB's `load_host` already wiped them. Simplification: skip `clear_file_rules`, rely on DB `load_host` order |

→ **Revised plan:** Drop `clear_file_rules` and `RuleSource` enum. DB load via `load_host` already replaces buckets. File load via `add_rule` then appends. Reload sequence in `reload_rules` is naturally idempotent if DB load runs first. Simpler.

**Updated steps:** Skip steps 1–4, 6 above. Implement only `load_dir` + wiring. Saves ~30 LoC.

## Security Considerations

- Validate file paths: `read_dir` already constrains to the directory; no path traversal risk from filenames alone.
- Symlink follow: leave as default (`std::fs::read_to_string` follows). Operators are expected to control the rules dir.
- YAML billion-laughs / anchor bombs: `serde_yaml` mitigates by default; existing `formats/yaml.rs` has same exposure. Acceptable.

## Next Steps

→ Phase 03: hot-reload via file watcher.
