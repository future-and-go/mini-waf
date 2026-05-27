---
phase: 2
title: "NodeState-Engine Bridge"
status: completed
priority: P1
effort: "3h"
dependencies: []
---

# Phase 2: NodeState-Engine Bridge

## Overview

`NodeState` currently has no reference to `WafEngine` or `RuleReloader`. When a worker receives synced rules, it cannot trigger a rule reload. This phase adds:

1. An optional `Arc<dyn RuleReloader>` callback for engine reloads
2. A `RuleRegistry` on NodeState for workers to store synced rules
3. A cluster-aware reload path that loads from in-memory registry (not DB)

### Red-Team Critical Fixes (from review)

- **BLOCKER #1**: `WafEngine::reload_rules()` reads from DB — workers in ForwardOnly mode have no DB. Must add a `reload_from_registry()` path that loads rules from the in-memory `RuleRegistry` on NodeState.
- **BLOCKER #2**: Phase 3 needs `RuleRegistry` on NodeState for `apply_sync_response()`. Must add it here.
- **Reentrancy constraint**: `on_rules_updated()` must never re-acquire NodeState locks.

## Requirements

- Functional: NodeState holds an optional engine callback + RuleRegistry for worker rule storage
- Functional: Worker reload path uses in-memory registry, NOT database
- Non-functional: Zero overhead when callback is None (standalone mode)

## Architecture

```
prx-waf/main.rs
  creates WafEngine (already Arc'd)
  creates ClusterNode::new(config)
  calls cluster_node.set_rule_reloader(engine.clone())
  passes cluster_node.state() to AppState
  spawns cluster_node.run()

NodeState
  rule_reloader: parking_lot::Mutex<Option<Arc<dyn RuleReloader>>>
  rule_registry: Arc<RwLock<RuleRegistry>>        // NEW: worker rule storage

RuleReloader trait
  on_rules_updated(version, Option<&RuleRegistry>) // CHANGED: pass registry for workers
  
Worker path:
  sync/rules.rs applies response → updates NodeState.rule_registry
  → calls notify_rules_updated(version) 
  → RuleReloader::on_rules_updated() loads from passed registry (not DB)
```

## Related Code Files

- Modify: `crates/waf-cluster/src/node.rs` — add `rule_reloader` + `rule_registry` fields
- Modify: `crates/waf-cluster/src/lib.rs` — add `set_rule_reloader()` to `ClusterNode`
- Modify: `crates/waf-engine/src/lib.rs` — extend `RuleReloader` trait with registry-aware reload
- Modify: `crates/prx-waf/src/main.rs` — call `set_rule_reloader()` before spawning cluster

## TDD: Tests First

1. Write test in `crates/waf-cluster/tests/engine_bridge_test.rs`:
   - Create a mock `RuleReloader` that records calls
   - Set it on `NodeState` via the new method
   - Call `node_state.notify_rules_updated(42)`
   - Assert mock received the call with version 42

2. Test: `notify_rules_updated` with `None` callback doesn't panic

3. Test: `NodeState.rule_registry` can be written and read concurrently (RwLock)

4. Test: mock RuleReloader receives registry reference and can read rules from it

## Implementation Steps

1. **Add `RuleRegistry` to NodeState** (`node.rs`):
   ```rust
   pub struct NodeState {
       // ... existing fields ...
       rule_reloader: parking_lot::Mutex<Option<Arc<dyn RuleReloader>>>,
       pub rule_registry: Arc<parking_lot::RwLock<RuleRegistry>>,
   }
   ```
   Initialize with empty `RuleRegistry::default()` in `NodeState::new()`.

2. **Extend `RuleReloader` trait** (`waf-engine/src/lib.rs`):
   ```rust
   #[async_trait::async_trait]
   pub trait RuleReloader: Send + Sync {
       async fn on_rules_updated(&self, version: u64) -> anyhow::Result<()>;
       async fn reload_from_registry(&self, registry: &RuleRegistry) -> anyhow::Result<()>;
   }
   ```
   Default impl of `reload_from_registry` for WafEngine: swap engine's internal RuleStore with the provided registry data.

3. **Add methods to NodeState**:
   ```rust
   pub fn set_rule_reloader(&self, reloader: Arc<dyn RuleReloader>) {
       *self.rule_reloader.lock() = Some(reloader);
   }

   pub async fn notify_rules_updated(&self, version: u64) -> anyhow::Result<()> {
       let reloader = self.rule_reloader.lock().clone();
       if let Some(r) = reloader {
           // Worker path: reload from in-memory registry (not DB)
           let registry = self.rule_registry.read();
           r.reload_from_registry(&registry).await?;
       }
       *self.rules_version.write() = version;
       Ok(())
   }
   ```
   Note: clone the reloader Arc BEFORE awaiting to avoid holding the Mutex across await.

4. **Add `set_rule_reloader()` to ClusterNode** (`lib.rs`):
   ```rust
   pub fn set_rule_reloader(&self, reloader: Arc<dyn RuleReloader>) {
       self.node_state.set_rule_reloader(reloader);
   }
   ```

5. **Wire in main.rs**: After creating `cluster_node` and `engine`:
   ```rust
   if let Some(ref node) = cluster_node {
       node.set_rule_reloader(Arc::clone(&engine) as Arc<dyn RuleReloader>);
   }
   ```

6. **Run tests** — bridge tests pass, `cargo check --workspace` clean

## Success Criteria

- [ ] `NodeState` has `rule_reloader` field AND `rule_registry` field
- [ ] `set_rule_reloader()` and `notify_rules_updated()` methods work
- [ ] Worker reload uses `reload_from_registry()` (not DB)
- [ ] `RuleReloader` trait has `reload_from_registry()` method
- [ ] Mock-based unit test passes
- [ ] `main.rs` wires engine into cluster node before spawn
- [ ] `cargo check --workspace` passes

## Risk Assessment

- Low-medium risk: adds registry field and new trait method
- Mitigation: `reload_from_registry` is additive — existing `on_rules_updated` still works for main nodes
- Constraint: `notify_rules_updated()` must not hold NodeState locks during await
