---
phase: 1
title: "Store faithful failure signaling (degraded ApplyResult + faithful Err)"
status: pending
effort: "2h"
---

# Phase 1: Store faithful failure signaling (degraded ApplyResult + faithful Err)

## Overview

Stop the store from fabricating fresh score-0 state on a Redis outage. `apply`
gains an explicit `ApplyResult.degraded` flag; the advisory `read` path returns
`Err` faithfully instead of silently serving the cache. The memory backend and
all other `RiskStore` impls always report `degraded: false`.

## Requirements

- Functional: on Redis failure/timeout, `apply` returns `Ok(ApplyResult { degraded:
  true, state, .. })` where `state` is the LRU cache hit if present else
  `RiskState::new(now_ms)`. On success `degraded: false`. `read` returns `Err` on
  Redis failure/timeout (no cache substitution).
- Non-functional: zero behavior change for the memory backend and for the healthy
  Redis path; `degraded` defaults `false` so existing decode/tests are unaffected.

## Architecture

- **`ApplyResult` gains `degraded: bool`** (`crates/waf-engine/src/risk/store/store_trait.rs:15`).
  It is not serialized (it is an in-process signal, not part of the Lua response
  `ApplyResponse` at `redis.rs:277`). Update the doc comment to say `degraded` is
  set only by backends that can transiently fail.
- **`RedisRiskStore::apply`** (`redis.rs:320-383`):
  - success arm (`redis.rs:350-359`) → `degraded: false`.
  - error arm (`redis.rs:360-370`) and timeout arm (`redis.rs:371-381`) → keep the
    `record_fail()` + `warn!`, but return `Ok(ApplyResult { degraded: true, state:
    <cache hit or RiskState::new(now_ms)>, is_new: <false if cache else true> })`.
  - empty-key arm (`redis.rs:321-326`) → `degraded: false` (not a failure).
  - Optional (recommended): at fn top, `if self.breaker_open() { record_fail();
    return Ok(degraded via cache/new); }` to skip the RTT during a sustained
    outage. Document the intent in code (invariant, no plan IDs).
- **`RedisRiskStore::read`** (`redis.rs:286-318`): replace the `Err(e) =>
  warn!(...); Ok(self.cache_lookup(key))` arm (`redis.rs:313-316`) with `Err(e) =>
  Err(e.context("risk redis: read"))`. `read` is not on the enforcement gate (the
  scorer calls `apply`, not `read`), so no caller regresses; grep confirms below.
- **`force_max`** (`redis.rs:385-431`) already returns `Err` on failure — no change.
- **Memory backend** (`store/memory.rs:131-165`): both `ApplyResult` sites
  (`memory.rs:133`, `memory.rs:164`) set `degraded: false`.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/store/store_trait.rs` (add field; test-site
  ctor at `store_trait.rs:219`; `NoopStore::apply` at `store_trait.rs:149-154`).
- Modify: `crates/waf-engine/src/risk/store/redis.rs` (apply arms, read arm,
  optional breaker short-circuit; test `basic_apply_and_read` at `redis.rs:604`).
- Modify: `crates/waf-engine/src/risk/store/memory.rs` (two ctor sites).
- No change: `crates/waf-engine/src/risk/store/conformance.rs` (constructs no
  `ApplyResult`; reads `result.state` only — field addition is source-compatible).

## Implementation Steps

1. Add `pub degraded: bool` to `ApplyResult`; update every construction site
   (memory ×2, redis ×5, `store_trait.rs:219` test, `NoopStore` ×1). Keep the
   healthy/empty/new arms `degraded: false`.
2. Rewrite the redis `apply` error + timeout arms to return `degraded: true` with
   cache-hit-or-fresh state (do not fabricate silently — the flag makes it explicit).
3. Make redis `read` return `Err` on failure/timeout; delete the cache-substitution
   arm. Verify no caller depended on read-swallows-error (grep step 4).
4. `grep -rn "\.read(" crates/waf-engine/src/risk` and the wider engine to confirm
   `RiskStore::read` callers tolerate `Err` (scorer uses `apply`, not `read`).
5. (Optional) add the `breaker_open()` short-circuit at `apply` top.
6. `cargo test -p waf-engine risk::store` — memory + trait tests green; redis
   unit tests (`lru_cache_*`, `breaker_*`) green.

## Success Criteria

- [ ] `ApplyResult.degraded` exists; all backends compile; memory/healthy paths
      report `false`.
- [ ] Unit test (no live Redis): a `RedisRiskStore` built against an unreachable
      URL — or a cache-preloaded store whose `apply` is forced through the error
      arm — returns `ApplyResult.degraded == true` and does **not** report a fresh
      score-0 as authoritative. Reuse the `REDIS_TEST_URL` gate pattern
      (`redis.rs:585`) only where a live server is required; otherwise unreachable-URL.
- [ ] `read` returns `Err` on Redis failure (asserted via unreachable-URL store).
- [ ] `cargo test -p waf-engine risk::store` green; `cargo clippy -p waf-engine
      --all-targets` clean.

## Risk Assessment

- Adding a struct field touches 8 construction sites — low risk, compiler-guided;
  `degraded: false` default preserves semantics everywhere but the two redis error
  arms.
- `read → Err` is a behavior change on an advisory path. Likelihood of a hidden
  caller: low (scorer uses `apply`). Mitigation: step 4 grep + keep the change
  scoped to the failure arm (success/None arms unchanged).

## Rollback

Revert the `apply` error arms to `degraded: false` (restores old fail-open) and
`read` to cache substitution. The `degraded` field is inert when always `false`,
so a partial rollback (leave the field, revert only the arms) is safe.
</content>
