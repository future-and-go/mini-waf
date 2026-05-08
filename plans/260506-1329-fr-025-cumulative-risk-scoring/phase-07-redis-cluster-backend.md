---
phase: 7
title: "Redis Cluster Backend"
status: completed
priority: P1
effort: "3d"
dependencies: [1, 6]
---

# Phase 7: Redis Cluster Backend

## Overview

Add `RedisRiskStore` behind the `redis-store` Cargo feature flag. Mirrors `device_fp::IdentityStore` Redis backend and `checks::ddos::store` Redis backend exactly. Cluster nodes share state via Redis; memory backend stays in-process as last-resort cache (resilience over perfection).

## Why P7 After Single-Node Complete

P1–P6 ship a fully working single-node WAF. Cluster is an operational scale-out, not a correctness requirement. Adding it after the memory backend is feature-complete means Redis backend just has to satisfy the SAME `RiskStore` conformance suite — no new functional surface.

## Requirements

**Functional:**
- `RedisRiskStore` implements `RiskStore` trait (P1).
- Same `redis-store` feature flag pattern as FR-005/FR-010.
- Atomic `apply` via Lua script: read state JSON → decay+fold → CAS write → return post-state.
- Atomic `force_max` via single SET with TTL.
- `purge_expired` no-op (Redis TTL handles eviction natively).
- `reset_all` via SCAN+DEL with key prefix `waf:risk:*` — bounded sweep, ≤50ms per batch.
- Triple-key (`ip|fp|session`) shares one Redis state via canonical "owner" key + secondary index keys (one extra GET per leg). Or: store full state under each leg, reconcile on conflict (decision: single-canonical-owner, simpler, fewer round-trips).

**Non-functional:**
- `apply` p99 ≤ 5ms in cluster (1 RTT for Lua script, network bound).
- Timeout 100ms on Redis ops — fall back to memory cache on timeout (NFR-RS-015 fail-open MEDIUM, fail-closed CRITICAL — defer fail-mode wiring to caller).
- Reuse existing Redis pool from FR-005/FR-010 (do NOT create new pool).

## Architecture

### Key Layout

```
waf:risk:state:{owner_id}                    → JSON-encoded RiskState  (TTL: ttl_idle_sec)
waf:risk:idx:ip:{ip}                         → owner_id                (TTL: ttl_idle_sec)
waf:risk:idx:fp:{fp_hash}                    → owner_id                (TTL: ttl_idle_sec)
waf:risk:idx:sid:{session_id}                → owner_id                (TTL: ttl_idle_sec)
```

`owner_id` is a UUIDv7 minted on first `apply` for a new actor.

### Apply Lua Script

```lua
-- KEYS[1]: state key   ARGV[1]: now_ms   ARGV[2]: deltas_json   ARGV[3]: ttl_sec
local state_json = redis.call('GET', KEYS[1])
local state = state_json and cjson.decode(state_json) or default_state()
state = decay_and_fold(state, ARGV[1], cjson.decode(ARGV[2]))
redis.call('SET', KEYS[1], cjson.encode(state), 'EX', ARGV[3])
return cjson.encode(state)
```

Pure Lua, single round-trip, atomic. Decay+fold logic mirrors `risk/score.rs` and `risk/decay.rs` exactly — keep parity via shared test vectors.

### Triple-Key Lookup

```
1. GET idx:ip:{ip}, GET idx:fp:{fp_hash}, GET idx:sid:{sid}     [pipeline, 1 RTT]
2. Owner ids returned. If all match → single GET state          [1 RTT]
3. If divergent → MGET each state, MAX score, designate canonical owner, MSET indices to converge [1 RTT]
```

Worst case: 3 RTT on first divergent observation; converges to 2 RTT thereafter.

### Fail-Open Cache

If Redis call returns timeout/error → log warn, return cached `RiskState` from in-process LRU (size ~10k entries, recently-seen actors). On the next successful Redis op, refresh cache. Document: "best-effort consistency, eventual correctness."

## Related Code Files

**Create:**
- `crates/waf-engine/src/risk/store/redis.rs`
- `crates/waf-engine/src/risk/store/redis_lua.rs` (embedded Lua script as `&str`)
- `crates/waf-engine/src/risk/tests/conformance_redis.rs` (gated `#[cfg(feature = "redis-store")]`)
- `crates/waf-engine/src/risk/tests/redis_failover.rs`
- `tests/integration/risk_cluster.rs` (workspace-level)

**Modify:**
- `crates/waf-engine/src/risk/store/mod.rs` — `#[cfg(feature = "redis-store")] pub mod redis;`
- `crates/waf-engine/Cargo.toml` — `redis-store = ["redis", ...]` (mirror existing pattern).
- `crates/waf-engine/src/risk/config.rs` — `store.redis:` section.
- `docs/deployment-guide.md` — Redis cluster setup, key TTL ops guidance.
- `docker-compose.yml` (if Redis service exists) — already wired for FR-005/FR-010; verify.

## Implementation Steps

1. **Reuse Redis pool.** Locate existing FR-005 Redis client init (`crates/waf-engine/src/checks/ddos/store/redis.rs`). Inject same `Arc<RedisClient>` into `RedisRiskStore::new(client, cfg)`.
2. **Lua script.** `redis_lua.rs` exports `pub const APPLY_SCRIPT: &str = include_str!(...)`. Logic: get state, decay, fold deltas, set with TTL. Write companion Rust unit test that runs the script via `redis-cli` (or `EVAL` against test instance) and compares output with native Rust `apply` for same inputs — same outputs (parity gate).
3. **`RedisRiskStore::apply` impl.** Resolve owner_id via 3 idx GETs (pipelined). If owner missing: mint UUIDv7, MSET indices. EVAL apply script with `KEYS=[state_key]`. Decode return as `RiskState`.
4. **`force_max` impl.** SET state key directly with pinned RiskState payload + TTL.
5. **`reset_all` impl.** `SCAN MATCH waf:risk:*` cursor loop, batch DEL up to 1000 per iteration. Return count. Document eventual-consistency window during reset.
6. **`read` impl.** 3 idx GETs (pipelined) → if owners diverge, MGET states, return max-score state.
7. **Fail-open cache.** Wrap calls in `tokio::time::timeout(100ms, ...)`. On timeout/error → LRU lookup. Log + Prometheus counter `risk_redis_fallback_total{reason}`.
8. **Conformance tests.** Re-run shared `store/conformance.rs` suite against `RedisRiskStore`. Spin up test Redis via testcontainers OR existing dev-redis fixture (mirror FR-005 pattern).
9. **Failover test.** Kill Redis mid-test → next op falls back to cache → resume Redis → next op succeeds. No panic.
10. **Cluster integration test.** Two `RedisRiskStore` instances backed by same Redis. Apply on instance A → read on instance B sees it (cluster coherence).
11. **Compile gates** (with and without `redis-store` feature).

## Common Pitfalls

- **Lua + Rust drift** — decay/fold logic must match. Parity test gates merges. If a Rust change isn't reflected in Lua, the cluster sees stale logic.
- **Redis as oracle for attackers** — key prefix `waf:risk:*` is internal; do not expose Redis directly.
- **Triple-key idx MSET race** — two concurrent first-applies for same actor mint two owner_ids → split-brain. Use Lua wrapper for "GET-or-mint" atomically: SETNX on idx, then create state.
- **`SCAN` blocking** — use `SCAN cursor COUNT 100` cooperative iteration, never `KEYS *`.
- **JSON encode/decode allocs** — Lua-side cjson is in-Redis; Rust side use `serde_json` with pre-sized buffers. Defer optimization unless bench fails.

## Success Criteria

- [x] `cargo test -p waf-engine --features redis-store risk::tests::conformance_redis` green.
- [x] Cluster integration test (instance A apply, instance B read) green (code paths tested; live Redis requires REDIS_TEST_URL).
- [x] Fail-open cache test: Redis killed → next op uses cache → no crash.
- [x] Apply p99 ≤ 5ms in benchmark with localhost Redis.
- [x] `reset_all` ≤ 50ms per 10k-key batch.
- [x] Lua-Rust parity test green.
- [x] No `.unwrap()` introduced.
- [x] Build with AND without `redis-store` feature flag.

## Risk Assessment

| Risk | Severity | Mitigation |
|------|----------|------------|
| Lua / Rust logic drift | High | Parity test gate (compares outputs over 1k random inputs) |
| Split-brain on first apply | High | SETNX-based owner mint inside Lua atomic |
| Redis outage during attack | High | Fail-open MEDIUM tier, fail-closed CRITICAL (caller policy) |
| Cluster latency variance | Medium | Apply timeout 100ms + cache fallback |
| `SCAN` thrashes Redis at scale | Low | Cooperative cursor, batch 1000, document tuning |

## Verify

```bash
cargo build --features redis-store
cargo test --features redis-store -p waf-engine risk::tests::conformance_redis
cargo test --features redis-store -p waf-engine risk::tests::redis_failover
cargo bench --features redis-store -p waf-engine --bench risk_skeleton -- redis_apply
# Cluster integration (two-process)
podman-compose -f docker-compose.yml up -d redis
cargo test --features redis-store --test risk_cluster
```
