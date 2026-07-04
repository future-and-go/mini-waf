---
phase: 2
title: "Single-RTT atomic Redis apply"
status: completed
priority: P2
dependencies: []
---

# Phase 2: Single-RTT atomic Redis apply (+ #199 max-score convergence)

<!-- Updated: Validation Session 1 - #199 convergence fix folded into this phase; Valkey test env confirmed -->

## Overview

`RedisRiskStore::apply()` currently makes 2 sequential Redis round-trips: `resolve_or_mint_owner` (MINT_OR_GET_OWNER_SCRIPT, redis.rs:414) then APPLY_SCRIPT (redis.rs:443). `force_max()` has the same shape (487, 498). This doubles hot-path latency, contradicts the module doc "All scripts are atomic single-RTT operations" (`redis_lua.rs:3`), and is non-atomic — index keys can be repointed to a different owner between the two calls. Merge owner resolution into APPLY_SCRIPT and FORCE_MAX_SCRIPT so each operation is one script, one RTT, atomic.

**Scope addition (Validation Session 1):** this phase also fixes **#199** — the current script converges colliding identity axes to the FIRST non-nil owner in KEYS order with no score comparison, letting attackers shed accumulated risk by rotating identity axes (session with score-90 owner + fresh IP with score-0 owner → indices repointed to the clean owner). The merged script instead selects the **max-score owner**, per the `store_trait.rs:29-33` contract and memory-store parity (`memory.rs:85` `max_by_key(clamped_score)`). #199's acceptance criterion 3 explicitly asks for convergence to be atomic with apply — which the single-script merge provides.

## Requirements

- Functional:
  - Owner convergence at apply/force_max time selects the owner whose state has the highest `clamped_score` among all owners found via the index keys (missing/expired state counts as score 0); all indices repoint to the winner. Mint path (no owner found) unchanged: SETNX claim with pre-minted UUID.
  - Decay, delta folding, contributor cap of 8, clean-streak counting, TTL refresh, `is_new` flag, and the JSON **state encoding stay byte-for-byte identical** (bug #198's encoding quirks included; #198 lands separately).
- Non-functional: `apply` and `force_max` each perform exactly one `invoke_async` (one RTT); owner resolution + convergence + state mutation are atomic within one Lua execution.

## Architecture

New script shapes (in `redis_lua.rs`):

- `APPLY_SCRIPT`: KEYS[1..N] = index keys (ip/fp/sid, only populated axes); ARGV = `new_owner_id` (pre-minted UUID from Rust), `key_prefix`, `now_ms`, `deltas_json`, `ttl_sec`, `min_clean_streak`, `decay_rate`, `max_decay`. Script flow:
  1. GET all index keys → collect distinct candidate `owner_id`s.
  2. None found → SETNX-claim mint path (logic as today's MINT_OR_GET_OWNER: claim KEYS[1], loser adopts winner).
  3. ≥1 found → GET each candidate's state (`key_prefix .. 'state:' .. owner_id`), decode, pick max `clamped_score` (nil state = 0; ties → first in KEYS order for determinism). Repoint ALL index keys to the winner with TTL.
  4. Compute `state_key` for the winner and run the existing decay/fold/persist logic unchanged.
  5. Return `{state, is_new, owner_id}` JSON — `owner_id` needed by Rust for `cache_update`.
- `FORCE_MAX_SCRIPT`: same owner-resolution/convergence preamble (steps 1–3); ARGV adds `until_ms`. Returns `owner_id` (Rust builds the max cache state locally as today, redis.rs:504-512). Convergence choice doesn't affect the forced score but must repoint indices consistently.
- `MINT_OR_GET_OWNER_SCRIPT` and `resolve_or_mint_owner()` are deleted once both callers are migrated (`read()` uses `lookup_owners`, not the mint script).

Losing owners' state keys are left to expire via TTL (select-max, not sum-merge — matches the memory store, which selects the max-score state rather than combining).

Constraint to document in the module doc: computing `state_key` inside Lua means state keys are not declared in KEYS. This is invalid for Redis Cluster slot routing — but the **current** code already touches index keys and state key in separate calls with no hash-tags, so it is equally cluster-unsafe today. The store uses a single `ConnectionManager` (non-cluster; deployment target is a single Valkey/Redis instance). Add a doc note stating the non-cluster assumption instead of pretending otherwise.

`key.is_empty()` is already guarded at the top of apply/force_max, so `index_keys()` is non-empty at invocation time.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/store/redis_lua.rs` — merged `APPLY_SCRIPT` and `FORCE_MAX_SCRIPT` with max-score convergence; delete `MINT_OR_GET_OWNER_SCRIPT`; fix the stale module doc at line 3 (it becomes true again).
- Modify: `crates/waf-engine/src/risk/store/redis.rs` — `apply()` builds one invocation (index keys as KEYS, prefix + minted UUID as ARGV); `force_max()` likewise; delete `resolve_or_mint_owner()` and `mint_owner_script` field; keep all existing fail-open cache fallback branches intact (their positions shift since there is now a single failure point).
- Modify: `crates/waf-engine/src/risk/store/conformance.rs` (or wherever `test_triple_index_max` lives) — add apply-time divergent-score convergence conformance test, both backends.

## Implementation Steps

1. Write the merged `APPLY_SCRIPT`: convergence preamble (steps 1–3 above) + existing decay/fold logic verbatim; thread winner `owner_id` into the state-key computation; extend return JSON with `owner_id`. Keep the decay/fold Lua character-identical to preserve `decay.rs`/`score.rs` parity.
2. Update `ApplyResponse` (redis.rs:363-367) with `owner_id: String`.
3. Rewrite `apply()`: mint UUID in Rust (`Self::mint_owner_id()` stays — Lua has no UUID source), single `prepare_invoke` with `index_keys(key)` as KEYS, single timeout, single ok/err/timeout match with the existing cache-fallback behavior.
4. Same for `FORCE_MAX_SCRIPT` / `force_max()`.
5. Delete `MINT_OR_GET_OWNER_SCRIPT`, `resolve_or_mint_owner`, `mint_owner_script` field; clean up now-unused imports.
6. Tests (run against the Valkey instance at `redis://127.0.0.1:6379` via `REDIS_TEST_URL` — protocol/Lua compatible, required proof per Validation Session 1):
   - Existing `basic_apply_and_read` still passes.
   - New conformance test (#199 acceptance): actor A (IP axis) accumulates score 90; actor B (fresh IP) score 0; apply with a key colliding both axes → resulting state has score ≥ 90's decayed value, indices converge to the high-score owner. Run against **both** memory and Redis backends.
   - Cross-axis convergence test: apply by IP, apply by IP+fp, read by fp sees the same owner state.
7. `REDIS_TEST_URL=redis://127.0.0.1:6379 cargo test -p waf-engine redis`.

## Success Criteria

- [x] `apply()` and `force_max()` each contain exactly one `invoke_async` call.
- [x] `MINT_OR_GET_OWNER_SCRIPT` and `resolve_or_mint_owner` deleted.
- [x] `redis_lua.rs` module doc ("atomic single-RTT") is accurate; non-cluster assumption documented.
- [x] (#199) Convergence selects the max-score owner; divergent-score conformance test passes on both backends.
- [x] State-encoding semantics unchanged (#198 untouched); existing Redis-gated tests pass against Valkey.
- [x] Fail-open fallback behavior (cache lookup on error/timeout) preserved.

## Risk Assessment

- **Semantic drift in the Lua merge** is the main risk — mitigate by moving the decay/fold block verbatim and pinning behavior with the conformance tests.
- **Convergence is now an intentional behavior change** (first-index → max-score): this is the #199 bug fix, contract-backed (`store_trait.rs:29-33`) and memory-store-paritied. Reviewers should see it called out in the PR body with the exploit scenario from #199.
- **#198 collision**: the merged script preserves #198's encoding quirks; whoever fixes #198 edits the merged script — flag in the PR description.
- Reading up to 3 candidate states inside the script adds Redis-side GETs, but they replace what `read()` already does over the network today; still one RTT total.
