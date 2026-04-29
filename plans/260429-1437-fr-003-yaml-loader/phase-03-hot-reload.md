# Phase 03 — Hot Reload Watcher

**Status:** done  **Priority:** P2  **Effort:** 0.2d  **ACs:** 3

## Context Links

- Loader: `crates/waf-engine/src/rules/custom_file_loader.rs` (phase 02)
- Existing watcher precedent: `crates/waf-engine/src/rules/manager.rs` (registry watcher) — read for `notify` usage style only
- `notify` crate: already a workspace dep

## Overview

Watch `<rules_dir>/custom/` for changes. On any create/modify/remove of a `*.yaml` file, debounce 500ms and trigger a full re-load of file rules. **Reverts:** before re-loading, must clear all previously file-loaded rules to avoid duplicate-id stacking.

This means **we DO need the `RuleSource` enum** that phase 02 considered dropping. Re-introduce it in phase 02's revised step list.

## Key Insights

- Hot-reload of file rules without `clear_file_rules` would accumulate stale rules on every save → memory leak + matching divergence.
- DB-load-clears-bucket only works on full reload of all hosts. A single file edit must NOT trigger a full DB reload (expensive + unrelated).
- **Conclusion:** keep `RuleSource::{Db, File}` field on `CustomRule`. `clear_file_rules` removes only `File`-tagged entries, then loader re-adds.

## Requirements

1. New struct: `CustomRuleFileWatcher` in `custom_file_loader.rs`.
2. `CustomRuleFileWatcher::new(rules_dir, engine: Arc<CustomRulesEngine>)` spawns a tokio task with a `notify::RecommendedWatcher`.
3. Debounce events with a 500ms timer (collect-then-flush).
4. On debounce flush:
   - Call `engine.clear_file_rules()`.
   - Call `custom_file_loader::load_dir(rules_dir)`.
   - For each rule, `engine.add_rule(rule)`.
   - Emit `info!("Reloaded N file-based custom rules")`.
5. Watcher is owned by `WafEngine`; dropped on engine shutdown.
6. Watcher creation failure → `warn!` and continue without watcher (do not abort startup).

## Architecture

```
┌─────────────────┐      events      ┌──────────────────┐
│ notify watcher  │ ──────────────► │ debounce timer   │
│ rules/custom/   │                  │ (500ms)          │
└─────────────────┘                  └────────┬─────────┘
                                              │ flush
                                              ▼
                              ┌────────────────────────────┐
                              │ clear_file_rules + load_dir │
                              │ + add_rule per result       │
                              └────────────────────────────┘
```

Implementation sketch:

```rust
pub struct CustomRuleFileWatcher {
    _watcher: notify::RecommendedWatcher,  // keep alive
    _task: tokio::task::JoinHandle<()>,
}

impl CustomRuleFileWatcher {
    pub fn spawn(
        rules_dir: PathBuf,
        engine: Arc<CustomRulesEngine>,
    ) -> anyhow::Result<Self> {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if matches!(res, Ok(_)) { let _ = tx.send(()); }
        })?;
        watcher.watch(&rules_dir.join("custom"), notify::RecursiveMode::NonRecursive)?;

        let task = tokio::spawn(async move {
            loop {
                if rx.recv().await.is_none() { break; }
                // Debounce: drain any further events that arrive within 500ms.
                let _ = tokio::time::timeout(Duration::from_millis(500), async {
                    while rx.recv().await.is_some() {}
                }).await;

                engine.clear_file_rules();
                match custom_file_loader::load_dir(&rules_dir) {
                    Ok(rules) => {
                        let n = rules.len();
                        for r in rules { engine.add_rule(r); }
                        tracing::info!("Reloaded {n} file-based custom rules");
                    }
                    Err(e) => tracing::warn!("File rule reload failed: {e}"),
                }
            }
        });

        Ok(Self { _watcher: watcher, _task: task })
    }
}
```

## Related Code Files

**Create:** addition to `custom_file_loader.rs` (or new sibling `custom_file_watcher.rs` if file >200 LoC).

**Modify:**
- `crates/waf-engine/src/rules/engine.rs` — add `RuleSource` enum + field (re-introduced from phase 02 sketch); add `clear_file_rules` method.
- `crates/waf-engine/src/engine.rs` — store watcher in `WafEngine::file_watcher: Option<CustomRuleFileWatcher>`; init in constructor.

## Implementation Steps

1. Re-introduce `RuleSource` (dropped in phase 02 revision) — minimal diff: enum + field, `from_db_rule` sets `Db`, parser sets `File`.
2. Implement `clear_file_rules` on `CustomRulesEngine`.
3. Implement `CustomRuleFileWatcher::spawn`.
4. Wire watcher init in `WafEngine` constructor (after first load).
5. Manual smoke test: edit a yaml, observe `info!` reload log within 1s.
6. Automated test: `tests/custom_rule_hot_reload.rs` — write file, await reload signal via channel, assert engine state.

## Todo

- [x] `RuleSource` enum + field (engine-internal on `RuleEntry`; `CustomRule` left untouched to avoid API churn)
- [x] `clear_file_rules` method
- [x] `CustomRuleFileWatcher::spawn`
- [x] Wire into `WafEngine` (new `start_file_watcher`, called from `prx-waf` after first reload)
- [x] Hot-reload integration test (`tests/custom_rule_hot_reload.rs`)

## Success Criteria

- AC-3 satisfied: editing a file triggers reload within 1s.
- No event-storm regression: rapidly saving 10 times causes ≤2 reload cycles (debounce).
- Watcher creation failure does not crash service.

## Risk Assessment

| Risk | Mitigation |
|---|---|
| Editor save dance (write temp + rename) fires multiple events | 500ms debounce coalesces |
| Race: clear_file_rules between match attempts | `DashMap` per-bucket lock; brief gap acceptable for non-critical reload |
| `notify` watcher dies silently on platform quirks | Log when channel closes; consider exposing health status (defer to follow-up) |

## Next Steps

→ Phase 04: docs + sample YAMLs.
