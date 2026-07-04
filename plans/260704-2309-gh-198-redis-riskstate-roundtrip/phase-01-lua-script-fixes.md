---
phase: 1
title: "Lua Script Fixes"
status: in-progress
effort: "S"
priority: P1
dependencies: []
---

# Phase 1: Lua Script Fixes

## Overview

Fix the two live serialization/semantics bugs in `APPLY_SCRIPT` so persisted
`RiskState` always round-trips through serde and `is_new` matches
`MemoryRiskStore` semantics.

## Requirements

- Functional: `is_new = true` on first apply for a key; decay contributor
  persists as serde-parseable JSON (`"kind":"Decay"`).
- Non-functional: no change to script call shape (KEYS/ARGV contract from
  PR #209 stays identical); no Rust-side changes needed.

## Architecture

Both bugs are inside `APPLY_SCRIPT` only. `FORCE_MAX_SCRIPT` uses truthiness
(`if state_json then`, redis_lua.rs:261) and creates no decay contributor —
verified unaffected. Owner-resolution blocks in both scripts also use
truthiness — unaffected.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/store/redis_lua.rs`

## Implementation Steps

1. **`is_new` fix** — redis_lua.rs:120. Delete the broken line
   `local is_new = (state_json == nil)` (Redis Lua `GET` returns boolean
   `false`, never `nil`, so the comparison is always false). Compute `is_new`
   from owner resolution instead, for exact `MemoryRiskStore` parity
   (memory.rs:139: `is_new` = no existing owner found on any axis):
   ```lua
   -- Parity with MemoryRiskStore: is_new means no owner existed on any
   -- index axis before this call (mint path), not "state key was absent".
   local is_new = (#candidates == 0)
   ```
   Place it right after the candidates loop (near redis_lua.rs:52), before the
   mint/convergence branch. Do NOT derive it from `state_json`: an owner
   converged from index keys whose state key already TTL-expired must report
   `is_new = false`, matching the memory backend. Within one atomic script
   execution the `claimed == 0` mint branch is unreachable, so
   `#candidates == 0` ⇔ mint.
   <!-- Updated: Validation Session 1 - is_new computed from owner mint, not state-key existence -->
   The decay guard at redis_lua.rs:123 (`if not is_new and ...`) keeps working
   unchanged: for a minted owner there is no prior state, `clean_streak` is 0,
   and decay is unreachable either way.

2. **Decay contributor kind** — redis_lua.rs:137. Replace
   ```lua
   kind = {Decay = cjson.null},
   ```
   with
   ```lua
   kind = 'Decay',
   ```
   Externally-tagged serde: unit variant `ContributorKind::Decay` is the JSON
   string `"Decay"` (mirror of decay.rs:45). Payload variants
   (`Rule`/`Seed`/`Signal`/`ChallengeCredit`) only ever enter Lua via
   `deltas_json` already serialized by serde and are re-encoded verbatim by
   cjson — no change needed for them.

3. Update the module doc comment if it claims anything now-stale (it already
   says decay/fold "mirrors decay.rs exactly — parity tests verify identical
   outputs"; after this fix that claim becomes true for the decay contributor).

4. Run `cargo fmt` + `cargo clippy -p waf-engine --features redis-store --lib`
   (scripts are string constants; this catches doc/format drift only).

## Success Criteria

- [x] `APPLY_SCRIPT` contains no `== nil` comparison against a `redis.call('GET', ...)` result
- [x] `is_new` derives from owner mint (`#candidates == 0`), not state-key existence — exact memory-store parity including the expired-state-key edge
- [x] Decay contributor encodes as `{"kind":"Decay","delta":...,"ts_ms":...}`
- [x] `cargo clippy -p waf-engine --features redis-store --lib` clean
- [ ] With `REDIS_TEST_URL` set (CI or operator-provided):
      `risk::store::redis::tests::basic_apply_and_read`,
      `risk::tests::conformance_redis::redis_apply_accumulates_score`,
      `risk::tests::conformance_redis::redis_store_passes_conformance` pass

## Risk Assessment

- **Behavior change:** `is_new` flips from always-false to correct. Consumers:
  `ScorerResult.is_new` (informational; no enforcement branches on it) and the
  `is_new`-based decay guard in the script itself (fresh state has
  `clean_streak = 0`, so decay was already unreachable for new actors —
  no scoring delta). Low risk.
- **Stored bad state:** actors whose state was persisted with
  `{"Decay":null}` before the fix remain unparseable until TTL expiry. No
  migration — TTL self-heals; `read` already treats parse failure per current
  error path (#201 tracks improving that path). Document in CHANGELOG only if
  release notes are cut before TTL horizon.
