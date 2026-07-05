---
phase: 2
title: "Honor DecayConfig across memory and redis backends"
status: completed
effort: 2h
---

# Phase 2: Honor DecayConfig across memory and redis backends

## Overview

Make `DecayConfig` (min_clean_streak, decay_rate, max_decay) actually drive decay
in both backends, instead of the hardcoded consts. Thread it by constructor
injection so the hot `RiskStore::apply` trait signature — and its ~50 test/conformance
call sites — stay untouched.

## Verified Context

- `DecayConfig { min_clean_streak: u32, decay_rate: u16, max_decay: u32 }`
  (`risk/config.rs:152-165`), `#[serde(default)]` on `RiskConfig.decay` (`config.rs:54-55`).
- `apply_decay(state, now_ms) -> i16` and `preview_decay(state, now_ms)` use consts
  `MIN_CLEAN_STREAK: u32 = 10`, `DECAY_RATE: i16 = 1`, `MAX_DECAY: i32 = 50`
  (`risk/decay.rs:12-72`).
- Memory: `store/memory.rs:153` `apply_decay(&mut state, now_ms)`.
- Redis: `store/redis.rs:32` imports the consts and feeds them at `redis.rs:343-345`
  into Lua `ARGV[6]=min_clean_streak`, `ARGV[7]=decay_rate`, `ARGV[8]=max_decay`
  (`store/redis_lua.rs:39-41`). The Lua body already reads these ARGVs — **it does
  not change**.
- `RedisRiskConfig` (`store/redis.rs:38-65`) has no decay field;
  `RedisStoreConfig::to_runtime_config(&self, ttl_secs)` (`config.rs:120-133`) builds it.
- `store.apply` call sites (why the trait signature stays fixed): production callers
  are only `scorer.rs:255` and `ingest/worker.rs:106`; the rest are tests —
  `store/memory.rs` (7), `store/redis.rs` (1), `store/conformance.rs` (18),
  `store/store_trait.rs` (1 NoopStore), `risk/tests/lifecycle.rs` (11),
  `risk/tests/redis_failover.rs` (5), `risk/tests/conformance_redis.rs` (6). Changing
  the signature would touch all of these; constructor injection touches none.
- `apply_decay` / `preview_decay` call sites to update (signature change): `store/memory.rs:153`,
  `risk/decay.rs` tests (5 `apply_decay` + 1 `preview_decay`), `risk/tests/lifecycle.rs:203`,
  `benches/risk_anomaly.rs:150`.

## Key Decisions

- **decay.rs signature:** `apply_decay(state: &mut RiskState, now_ms: i64, decay: &DecayConfig) -> i16`
  and `preview_decay(state, now_ms, decay)`. Body reads `decay.min_clean_streak`,
  `i32::from(decay.decay_rate)`, and `i32::try_from(decay.max_decay).unwrap_or(100)`
  as the floor (validate() enforces `max_decay <= 100`, keeping the cast safe;
  the fallback is defensive).
- **Consts as defaults only:** keep the three `decay.rs` consts (tests and benches
  reference them as expected values) but they no longer feed runtime decay. Their
  numeric equals already live in `config.rs` default fns (`default_min_clean_streak`
  = 10, etc.). Do not delete — deleting breaks `lifecycle.rs`/`conformance.rs`/bench
  assertions and is out of scope.
- **Memory store holds decay:** add `decay: DecayConfig` field. Keep `new()` /
  `Default` = `DecayConfig::default()` so existing `MemoryRiskStore::new()` test call
  sites compile unchanged; add `MemoryRiskStore::with_decay(decay: DecayConfig)` for
  production. `apply` passes `&self.decay` to `apply_decay`.
- **Redis store holds decay:** add `decay: DecayConfig` to `RedisRiskConfig`
  (`Default` = `DecayConfig::default()`), map it in
  `RedisStoreConfig::to_runtime_config` (which already has `RiskConfig` context via
  its caller — pass `decay` in). `apply` feeds `self.cfg.decay.*` into the three
  ARGVs instead of the consts; drop the `use crate::risk::decay::{...}` import.
- **decay_rate: 0 disables decay** through existing arithmetic (see plan Key
  Decisions) — no new branch in decay.rs or Lua.

## Implementation Steps

1. `decay.rs`: add `decay: &DecayConfig` param to `apply_decay` and `preview_decay`;
   replace const reads with `decay.*`; update the module's 6 test calls to pass
   `&DecayConfig::default()`.
2. `store/memory.rs`: add `decay: DecayConfig` field; init to default in `new()`;
   add `with_decay(decay)`; pass `&self.decay` at the `apply_decay` call (line ~153).
3. `store/redis.rs`: add `decay: DecayConfig` to `RedisRiskConfig` + its `Default`;
   replace the const ARGVs (lines ~343-345) with `self.cfg.decay.min_clean_streak`,
   `self.cfg.decay.decay_rate`, `self.cfg.decay.max_decay`; remove the decay-const import.
4. `config.rs`: extend `RedisStoreConfig::to_runtime_config` to accept/attach
   `decay: DecayConfig` (thread `RiskConfig.decay` from the caller).
5. `engine.rs`: at the current store-construction site build the memory store with
   `MemoryRiskStore::with_decay(self.risk_cfg.load().decay.clone())` (RE-GREP the exact
   site — merges #209/#210/#211 shifted lines; GH-196 phase-01 references ~257-271).
   With today's default `risk_cfg` this is a no-op behaviorally but connects the seam.
6. `benches/risk_anomaly.rs:150` and `risk/tests/lifecycle.rs:203`: pass
   `&DecayConfig::default()` to `apply_decay`.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/decay.rs`
- Modify: `crates/waf-engine/src/risk/store/memory.rs`
- Modify: `crates/waf-engine/src/risk/store/redis.rs`
- Modify: `crates/waf-engine/src/risk/config.rs` (`to_runtime_config` only — validate is Phase 3)
- Modify: `crates/waf-engine/src/engine.rs` (store construction site — re-grep)
- Modify (test/bench arg only): `crates/waf-engine/benches/risk_anomaly.rs`, `crates/waf-engine/src/risk/tests/lifecycle.rs`
- Unchanged: `crates/waf-engine/src/risk/store/redis_lua.rs` (Lua already ARGV-driven)

## Success Criteria

- [ ] Memory `apply_decay` uses configured `decay_rate`; a store built with
      `decay_rate: 3` sheds 3/clean-request; `decay_rate: 0` sheds nothing.
- [ ] Redis ARGVs carry `cfg.decay`; no `DECAY_RATE`/`MIN_CLEAN_STREAK`/`MAX_DECAY`
      const reads remain in `redis.rs`.
- [ ] `cargo test -p waf-engine` green; `cargo build -p waf-engine --features redis-store` green.

## Risk Assessment

- Likelihood med / impact low. Mostly mechanical signature + field plumbing.
- Cast risk: `max_decay: u32` → floor `i32`. Bounded by validate() (`<= 100`); use
  `try_from`/`unwrap_or(100)` so an unvalidated construction cannot panic.
- Cross-plan: `engine.rs` construction site also edited by GH-196 — coordinate at merge.

## Rollback

Revert store fields + decay.rs signature; `apply_decay` returns to const-driven.
No persisted-state format change (Lua unchanged, RiskState schema unchanged).
</content>
