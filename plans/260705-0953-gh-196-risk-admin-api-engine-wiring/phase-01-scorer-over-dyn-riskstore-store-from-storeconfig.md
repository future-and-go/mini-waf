---
phase: 1
title: "Scorer over dyn RiskStore + store from StoreConfig"
status: completed
priority: P1
dependencies: []
---

# Phase 1: Scorer over dyn RiskStore + store from StoreConfig

## Overview

Make the engine's risk store selectable from `StoreConfig` instead of the
hardcoded `MemoryRiskStore`. This requires the scorer to be generic over a
trait object and swappable after construction.

## Requirements

- Functional: `store.backend: redis` in risk.yaml produces a `RedisRiskStore`;
  `memory` (default) produces `MemoryRiskStore` with the purge loop running.
- Non-functional: no measurable hot-path regression — one `ArcSwap` load per
  `inspect()` (same cost class as the existing `risk_cfg` load).

## Architecture

- `Scorer<S: RiskStore + ?Sized>` — relax the bound so `Scorer<dyn RiskStore>`
  compiles (`store: Arc<S>` already supports unsized `S`).
- Engine field changes `Arc<Scorer<MemoryRiskStore>>` →
  `ArcSwap<Scorer<dyn RiskStore>>` (`crates/waf-engine/src/engine.rs:161`).
  Construction still installs a memory-backed scorer (default, disabled config).
- New engine helper `fn build_risk_store(cfg: &RiskConfig) -> Arc<dyn RiskStore>`:
  - `backend == "redis"` → `RedisRiskStore` from `cfg.to_runtime_config(cfg.ttl_secs)`
    (`risk/config.rs:122`); on connect error, `warn!` and fall back to memory
    (fail-soft, matching other subsystems).
  - otherwise → `Arc<MemoryRiskStore>` + `start_purge_loop(ttl_ms, gc_interval_secs)`
    (`store/memory.rs:44`; note it takes `&Arc<Self>`, so call before unsizing).
- Scorer rebuild helper: building a new scorer must re-attach the canary layer
  (`set_canary(Arc::clone(&self.risk_canary))`) and seed layer if configured, so
  extract the construction block at `engine.rs:257-271` into a reusable fn.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/scorer.rs` (bound relaxation)
- Modify: `crates/waf-engine/src/engine.rs` (field type, construction, `inspect()` scorer access at ~line 705)
- Modify: `crates/waf-engine/src/risk/config.rs` only if `to_runtime_config` needs the cache-capacity/op-timeout knobs it already maps

## Implementation Steps

1. Relax `Scorer` bound to `S: RiskStore + ?Sized` (struct + impl blocks).
2. Change engine field to `ArcSwap<Scorer<dyn RiskStore>>`; update construction
   and every `self.scorer.` access (`engine.rs:705` and canary/scorer helpers).
3. Add `build_risk_store(cfg)` + `build_scorer(cfg, store)` helpers on the engine
   (or in `risk/mod.rs`), wiring purge loop for memory and redis config mapping.
4. `cargo test -p waf-engine` — existing scorer/engine tests still green.

## Success Criteria

- [ ] `Scorer<dyn RiskStore>` compiles; engine tests pass unchanged.
- [ ] Unit test: `build_risk_store` returns memory store by default and honors
      `backend: redis` (constructor path; connection exercised in Phase 5).
- [ ] Memory purge loop verified started (test via short ttl + purge observation
      or a `is_purge_running` style probe — implementer's choice).

## Risk Assessment

- Unsizing `Arc<MemoryRiskStore>` → `Arc<dyn RiskStore>` after `start_purge_loop`
  is order-sensitive; document in code.
- `ArcSwap<Scorer<...>>` requires `Scorer: Sized` inside `Arc` — fine, the trait
  object is inside the scorer, not the scorer itself.
