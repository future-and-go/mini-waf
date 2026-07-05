---
phase: 4
title: "Actor clear/credit wired to the store"
status: pending
priority: P1
dependencies: [1, 2]
---

# Phase 4: Actor clear/credit wired to the store

## Overview

Make `clear_risk_actor` and `credit_risk_actor` (`crates/waf-api/src/risk_api.rs:180-195`)
mutate the engine's live risk store instead of returning unconditional
`success:true`. `list_risk_actors` stays a documented stub (out of scope).

## Requirements

- Functional: `DELETE /api/risk/actors/:id` removes the actor's state;
  `POST /api/risk/actors/:id/credit` applies a negative delta (body:
  `{ "amount": <1..=100> }`, default 25 — matches challenge-credit magnitude).
- `:id` is the actor IP (the request-path scorer keys on client IP,
  `scorer.rs:264-278`); invalid IP → 400. No false success: store errors → 5xx.

## Architecture

- New trait method `RiskStore::clear(&self, key: &RiskKey) -> anyhow::Result<bool>`
  (returns whether anything was removed):
  - `MemoryRiskStore`: remove all indices resolving to the actor (IP + any
    fp/session pointing at the same `Arc` — follow the triple-index doc in
    `store_trait.rs`).
  - `RedisRiskStore`: Lua script — resolve owner via index key, `DEL` owner
    state + index keys. Follow existing script conventions in `redis_lua.rs`
    (single round-trip, key prefix, TTL discipline).
- Credit: `store.apply(&key, &[Contributor::new(ContributorKind::AdminCredit, -amount, now_ms)], now_ms)`.
  Add unit variant `ContributorKind::AdminCredit`; verify it round-trips
  through the redis Lua encode/decode path (GH-198 fixed `Decay` — same shape).
  Note `fold` (`score.rs`) resets `clean_streak` and `reclamp` floors at 0 —
  desired semantics for an explicit admin credit (decay floor does not apply
  to explicit credits per `decay.rs:6`).
- Engine exposure: `WafEngine::risk_clear_actor(ip)` / `risk_credit_actor(ip, amount)`
  thin wrappers over the active scorer's store (Phase 1 gives `Arc<dyn RiskStore>`
  access) — `AppState.engine` is already available in handlers (`state.rs:19`).

## Related Code Files

- Modify: `crates/waf-engine/src/risk/store/store_trait.rs` (trait + docs)
- Modify: `crates/waf-engine/src/risk/store/memory.rs`, `store/redis.rs`, `store/redis_lua.rs`
- Modify: `crates/waf-engine/src/risk/state.rs` (`ContributorKind::AdminCredit`)
- Modify: `crates/waf-engine/src/engine.rs` (wrappers), `crates/waf-api/src/risk_api.rs` (handlers)
- Modify: conformance suites (`risk/tests/conformance*.rs`) — clear + AdminCredit cases for both backends

## Implementation Steps

1. Add `ContributorKind::AdminCredit`; extend Lua encode/decode + serde tests.
2. Add `clear` to trait; implement memory then redis (script + registration).
3. Engine wrappers; rewrite the two handlers (parse IP, call engine, map errors).
4. Conformance: clear removes state on both backends; credit lowers score and
   round-trips contributor kind.

## Success Criteria

- [ ] Clear on a scored actor → next read is `None`/fresh state (both backends,
      redis case gated on `REDIS_TEST_URL`).
- [ ] Credit lowers clamped score by `amount` (floored at 0) and survives a
      redis round-trip.
- [ ] No endpoint returns success without a corresponding store mutation.

## Risk Assessment

- Redis `clear` must delete ALL index keys or a stale fp/session index resurrects
  the actor — mirror the merge-on-collide key layout exactly.
- New enum variant changes the wire shape stored in redis: additive (old data
  never contains it), so no migration needed, but keep serde tag format identical.
