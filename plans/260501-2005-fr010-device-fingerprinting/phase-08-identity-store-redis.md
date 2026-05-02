# Phase 08 — IdentityStore Redis Impl (Feature-Flagged)

**Status:** in-progress (core impl done; bench + deployment-guide pending) | **Priority:** P1 | **Effort:** S | **Blocked by:** phase-05

## Context

v2 multi-node deployments need shared identity state. Redis impl behind feature flag `redis-store`, off by default. Reuses conformance suite from phase-05 unchanged.

## Requirements

### Functional
- `RedisIdentityStore` impls same `IdentityStore` trait
- Backed by `redis-rs` with connection pool
- Storage scheme:
  - `wafp:fp:{fp_key}` → hash w/ HSET fields: `first_seen`, `last_seen`, `ip_set`, `ua_set` (use Redis Streams or compact JSON)
  - `wafp:ips:{fp_key}` → sorted set: score=ts, member=ip (sliding window via ZREMRANGEBYSCORE)
  - `wafp:uas:{fp_key}` → sorted set: score=ts, member=ua_hash
- TTL set on every write = configured `ttl_secs`
- All Redis ops wrapped w/ `tokio::time::timeout` (default 50ms)
- Circuit breaker: N consecutive timeouts → temporary degrade to memory store + warn

### Non-functional
- Pipelining where possible (observe = 1 round trip via MULTI/EXEC)
- Connection pool size configurable
- Optional TLS to Redis

## Files

**Created:**
- `crates/waf-engine/src/device_fp/identity/redis.rs`
- `crates/waf-engine/Cargo.toml` — `[features] redis-store = ["dep:redis"]`, `[dependencies] redis = { version = "...", optional = true, features = ["tokio-comp", "tls-rustls"] }`

**Modified:**
- `crates/waf-engine/src/device_fp/config.rs` — `redis` config block validation
- `crates/waf-engine/src/device_fp/identity/mod.rs` — `#[cfg(feature = "redis-store")]` re-export

## Steps

1. Add `redis` optional dep + feature flag
2. Implement `RedisIdentityStore::new(config) -> Result<Self>` w/ pool init + ping
3. Implement `observe` via pipelined ZADD + ZREMRANGEBYSCORE + ZCARD + EXPIRE in one MULTI/EXEC
4. Implement `lookup` via parallel HGETALL + ZRANGE
5. Implement `purge_expired` (no-op — Redis TTL handles it; return 0)
6. Implement timeout wrapper + circuit breaker (`atomic::AtomicU32` consecutive failure counter; threshold 5 → degrade)
7. Run phase-05 conformance suite against `RedisIdentityStore` via testcontainers-rs Redis 7
8. Bench round-trip latency vs memory; document p99
9. Update `docs/deployment-guide.md` w/ Redis setup, key prefix conventions

## Todos

- [x] Cargo feature + redis dep (`redis 0.27` w/ `tokio-comp`, `connection-manager`, `tls-rustls`, `script`)
- [x] `RedisIdentityStore` impl (real, not stub)
- [x] Atomic observe via Lua `EVAL` (single round-trip; supersedes MULTI/EXEC for first/last_seen min/max logic)
- [x] Timeout wrapper + circuit breaker (`AtomicU32`, threshold-tripped warn, `breaker_open()` accessor)
- [x] Conformance test wired — gated on `REDIS_TEST_URL` env (testcontainers omitted; YAGNI — env var works for CI)
- [ ] Bench p99 round-trip latency
- [ ] Deployment guide updates
- [ ] CI job: `cargo test --features redis-store` w/ Redis service

## Success Criteria

- All 12 phase-05 conformance scenarios pass on `RedisIdentityStore`
- Round-trip p99 documented (target <2ms LAN, <10ms cross-AZ)
- Circuit breaker triggers + degrade verified by killing Redis mid-test
- Default build (no flag) has zero `redis` crate footprint

## Risks

- Network latency adds to global p99 budget → circuit breaker mandatory; degrade path tested
- Redis OOM under DDoS → max-memory + LRU eviction policy documented; key prefix isolation
- Schema migration: bake `wafp:v1:` prefix; document migration plan for v2 schema

## Security

- Redis AUTH supported via config; password loaded from env var, never logged
- TLS to Redis optional but recommended in deployment guide
- Sanitize fp_key in error logs (it's a hash, but still)

## Next

Phase 09 — final coverage gate + bench + docs sync.
