---
phase: 3
title: "Rule Sync End-to-End"
status: completed
priority: P1
effort: "6h"
dependencies: [1, 2]
---

# Phase 3: Rule Sync End-to-End

## Overview

Rule sync helpers exist (`RuleChangelog`, `handle_sync_request`, `apply_sync_response`) but nothing invokes them. This phase wires rule sync end-to-end:

1. Main records rule changes to `RuleChangelog` when rules are modified via API
2. Workers periodically send `RuleSyncRequest` to main
3. Main responds with incremental delta or full snapshot
4. Workers apply the response and call `notify_rules_updated()`

## Requirements

- Functional: Rules created/deleted via Admin API propagate to workers within `rules_interval_secs`
- Functional: Workers get full snapshot on first connect (version 0 → current)
- Non-functional: Incremental sync for small changes; lz4-compressed full snapshot for large diffs

## Architecture

```
Main Node:
  API POST /api/rules → waf_storage::create_rule()
    → RuleChangelog::record_change(RuleAdded { id, rule })
    → engine.reload_rules()

Worker Node:
  run_rule_sync_loop() (every rules_interval_secs):
    → send RuleSyncRequest { current_version }
    → receive RuleSyncResponse { version, changes/snapshot }
    → apply_sync_response() updates local RuleRegistry
    → node_state.notify_rules_updated(new_version)
```

## Related Code Files

- Modify: `crates/waf-cluster/src/sync/rules.rs` — add `run_rule_sync_loop()`
- Modify: `crates/waf-cluster/src/transport/server.rs` — real `handle_rule_sync_request()` (replace stub)
- Modify: `crates/waf-cluster/src/transport/client.rs` — real `handle_rule_sync_response()` (replace stub)
- Modify: `crates/waf-cluster/src/node.rs` — add `RuleChangelog` to `NodeState`
- Modify: `crates/waf-cluster/src/lib.rs` — spawn `run_rule_sync_loop` in `ClusterNode::run()`
- Modify: `crates/waf-api/src/rules_api.rs` — call `record_change()` after rule CRUD
- Read: `crates/waf-cluster/src/sync/rules.rs` — existing helpers

## TDD: Tests First

1. **Unit test** (`crates/waf-cluster/tests/rule_sync_e2e.rs`):
   - Create two `NodeState` instances (main + worker)
   - Record 3 rule changes on main's `RuleChangelog`
   - Worker sends `RuleSyncRequest { version: 0 }`
   - Main processes with `handle_sync_request()` → returns full snapshot
   - Worker applies with `apply_sync_response()` → version matches main
   - Verify mock `RuleReloader::on_rules_updated()` called on worker

2. **Incremental test**:
   - Worker at version 5, main at version 8
   - Assert response contains only 3 incremental changes (not full snapshot)

3. **Full snapshot fallback test**:
   - Worker at version 1, main at version 600 (beyond 500-entry ring buffer)
   - Assert response is full lz4-compressed snapshot

## Implementation Steps

1. **Add `RuleChangelog` to `NodeState`** (`node.rs`):
   - Add `rule_changelog: Arc<parking_lot::RwLock<RuleChangelog>>` field
   - Initialize with default empty changelog

2. **Wire `handle_rule_sync_request`** (`transport/server.rs`):
   - Replace stub with call to `sync::rules::handle_sync_request()`
   - Read from `node_state.rule_changelog`
   - Serialize response and send back on the QUIC stream

3. **Wire `handle_rule_sync_response`** (`transport/client.rs`):
   - Replace stub with call to `sync::rules::apply_sync_response()`
   - Update `node_state.rules_version`
   - Call `node_state.notify_rules_updated(new_version).await`

4. **Implement `run_rule_sync_loop`** (`sync/rules.rs`):
   ```rust
   pub async fn run_rule_sync_loop(
       state: Arc<NodeState>,
       interval_secs: u64,
       main_tx: mpsc::Sender<ClusterMessage>,
   ) {
       let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
       loop {
           interval.tick().await;
           if state.role() == NodeRole::Worker {
               let version = *state.rules_version.read();
               let req = ClusterMessage::RuleSyncRequest(RuleSyncRequest {
                   current_version: version,
               });
               if main_tx.send(req).await.is_err() {
                   tracing::warn!("Rule sync: main channel closed");
               }
           }
       }
   }
   ```

5. **Spawn in `ClusterNode::run()`** (`lib.rs`):
   - After dialing seeds, spawn `run_rule_sync_loop` for each peer sender

6. **API integration** (`waf-api/src/rules_api.rs`):
   - After `create_rule()` / `delete_rule()` / `update_rule()`, check if `AppState.cluster_state` is `Some`
   - If so, call `cluster_state.rule_changelog.write().record_change(...)` 

7. **Run tests** — all rule sync tests pass

## Success Criteria

- [ ] Workers periodically send `RuleSyncRequest` to main
- [ ] Main responds with incremental delta or full snapshot
- [ ] Workers apply changes and call `notify_rules_updated()`
- [ ] API rule CRUD records changes to `RuleChangelog`
- [ ] Unit tests cover: full snapshot, incremental sync, empty (no-op) sync
- [ ] `cargo test -p waf-cluster` passes
- [ ] `cargo check --workspace` passes

## Risk Assessment

- Medium risk: most complex phase — touches 6 files across 3 crates
- Mitigation: helpers already exist and are tested; this phase wires them
- Pitfall: race between API rule write and changelog read → `RwLock` prevents this
- Pitfall: worker rule_reloader not set → `notify_rules_updated` is a no-op (safe)
