---
phase: 4
title: "Hot Reload of .data Files"
status: pending
priority: P2
effort: "4h"
dependencies: [2, 3]
---

# Phase 4: Hot Reload of .data Files

## Overview

Operators edit threat lists (e.g. add new entry to `restricted-files.data`) without restarting the WAF. The existing watcher in `crates/waf-engine/src/rules/hot_reload.rs` already covers `*.yaml` recursively — extend it to `*.data` and trigger a recompile for affected rules.

V1 simplification (YAGNI): `.data` change triggers a full rules reload via the existing mechanism. Per-rule selective rebuild is V2 — only if profiling shows full reload latency hurts.

## Requirements

- Watcher dispatches on `*.data` file events (create/modify/delete inside `rules_dir/**`).
- Debounce reuses the existing setting (`HotReloadConfig::debounce_ms` — already in code).
- TDD test: write a temp `restricted-files.data`, write to it at runtime, assert engine evaluation changes within `2 * debounce_ms`.
- Reverse-index `data_path → rule_ids` built during load (already in `DataFileRegistry` from Phase 2 — wire it up).

## Architecture

```rust
// crates/waf-engine/src/rules/hot_reload.rs
fn is_rule_or_data_file(path: &Path) -> bool {
    let ext = path.extension().and_then(|s| s.to_str());
    matches!(ext, Some("yaml") | Some("yml") | Some("data"))
}

// In event handler:
match path.extension().and_then(|s| s.to_str()) {
    Some("yaml") | Some("yml") => trigger_full_reload(),
    Some("data") => trigger_full_reload(), // V1: same path; V2: selective
    _ => {}
}
```

V2 hook (not implemented now, keep extension-friendly):

```rust
// pseudo for future: per-rule selective rebuild
fn rebuild_affected_rules(data_path: &Path, registry: &DataFileRegistry) -> Result<()> {
    let rule_ids = registry.lookup_rules_for_data(data_path);
    for rule_id in rule_ids { recompile_one(rule_id)? }
    Ok(())
}
```

## Related Code Files

- **Modify:**
  - `crates/waf-engine/src/rules/hot_reload.rs` (file-filter predicate + event dispatch)
  - `crates/waf-engine/tests/custom_rule_hot_reload.rs` (extend with `.data` reload test)

## Implementation Steps

1. **TDD test first** — extend `custom_rule_hot_reload.rs` with a `data_file_reload_picks_up_new_pattern` case:
   - Setup: temp `rules_dir` with a YAML rule `pm_from_file: test.data` and a `data/test.data` containing `["forbidden"]`.
   - Start engine, send `RequestCtx { path: "/forbidden" }` → Block.
   - Send `RequestCtx { path: "/newbad" }` → Pass (not yet in list).
   - Append `"newbad"` to `data/test.data`.
   - Sleep `2 * debounce_ms`.
   - Send `RequestCtx { path: "/newbad" }` → Block.
   - Test FAILS on current code (watcher ignores `.data`).

2. Update `is_rule_file` predicate in `hot_reload.rs` to include `data` extension.

3. Confirm event dispatch reuses the existing debounce + reload flow. No new code path needed beyond predicate.

4. Verify with the new test + existing hot-reload tests + full suite.

5. Document in `crates/waf-engine/CLAUDE.md` (or relevant `README`): "Editing `*.data` files triggers a debounced rules reload — no restart needed."

## Success Criteria

- [ ] `data_file_reload_picks_up_new_pattern` test passes.
- [ ] Existing `custom_rule_hot_reload.rs` tests still pass.
- [ ] Editing `rules/owasp-crs/data/restricted-files.data` at runtime (manual smoke test) shows rule behaviour change within one debounce window.
- [ ] `cargo fmt --all -- --check` clean.

## Risk Assessment

| Risk | Mitigation |
|------|------------|
| Rapid edits cause reload thrash | Existing debounce mechanism applies — same as YAML. |
| Full reload is too slow under many rules | Acceptable for V1. If perf issue surfaces, move to per-rule selective rebuild (`DataFileRegistry.lookup_rules_for_data`). |
| Partial write of `.data` file mid-reload races | `DataFileRegistry` mtime+size check ignores no-op events; full reload re-reads atomically. Same risk model as `.yaml`. |

## Out of Scope

- Per-rule selective rebuild (V2).
- File-write atomicity guarantees beyond what the YAML hot-reload provides today.
