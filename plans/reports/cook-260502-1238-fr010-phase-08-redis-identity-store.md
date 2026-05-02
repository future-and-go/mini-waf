# Cook — FR-010 phase-08 Redis Identity Store

**Mode:** `--auto` | **Branch:** `feat/fr-010` | **Date:** 2026-05-02

## Delivered

- `redis 0.27` optional dep behind `redis-store` feature (`tokio-comp`, `connection-manager`, `tls-rustls`, `tokio-rustls-comp`, `script`).
- `crates/waf-engine/src/device_fp/identity/redis.rs` — full impl replacing phase-02 stub.
  - `RedisConfig` (url, key_prefix, ttl_secs, window_secs, op_timeout, breaker_threshold).
  - `RedisIdentityStore::new` opens client + `ConnectionManager` + PING.
  - `observe` — atomic Lua `EVAL`, one round-trip: ZADD/ZREMRANGEBYSCORE/ZCARD on `ips`/`uas` zsets, HGET/HSET min/max on `fp` hash, EXPIRE on all three.
  - `lookup` — pipelined HGET×2 + ZCARD×2.
  - `purge_expired` — SCAN `<prefix>fp:*`, HGET `last_seen`, DEL trio when stale.
  - Timeout wrapper around every Redis future; `AtomicU32` consecutive-failure breaker; `breaker_open()` accessor for caller-side degrade.
- Conformance test re-uses phase-05 12-scenario suite, gated on `REDIS_TEST_URL` env (skipped hermetically when unset). Per-run unique `key_prefix` avoids cross-run clobber.

## Validation

- `cargo check -p waf-engine` — clean (default).
- `cargo check -p waf-engine --features redis-store` — clean.
- `cargo clippy -p waf-engine --all-targets -- -D warnings` — clean (default).
- `cargo clippy -p waf-engine --all-targets --features redis-store -- -D warnings` — clean.
- `cargo test -p waf-engine --features redis-store --lib device_fp::identity` → 4 passed (memory conformance + redis test skipped via env gate).

## Design Decisions

1. **Lua `EVAL` over MULTI/EXEC.** Plan said pipelined MULTI/EXEC; switched to Lua because `clock_skew_tolerance` conformance scenario requires `first_seen = min(existing, ts)` semantics which MULTI/EXEC cannot express atomically without a follow-up CAS loop. EVAL is one round-trip too.
2. **Scan-based `purge_expired`.** Plan said no-op (rely on Redis TTL). Conformance `purge_expired_count` and `ttl_expiry` scenarios assert observation-ts-based expiry, which Redis wall-clock TTL doesn't satisfy when `ts` is in the distant past. SCAN + last_seen check honours the trait contract; Redis TTL still acts as the primary reaper.
3. **testcontainers omitted.** YAGNI: env-var gate (`REDIS_TEST_URL`) is enough for CI matrix and keeps dev-deps thin. Easy to add later if needed.

## Pending (deferred from plan)

- Bench p99 round-trip latency (criterion bench).
- `docs/deployment-guide.md` Redis section.
- CI workflow job for `--features redis-store` w/ Redis service container.

## Files Touched

- `crates/waf-engine/Cargo.toml` — `redis` optional dep, `redis-store = ["dep:redis"]`.
- `crates/waf-engine/src/device_fp/identity/redis.rs` — full impl (was 40-line stub, now 290-line real impl).
- `plans/260501-2005-fr010-device-fingerprinting/phase-08-identity-store-redis.md` — todo checkboxes.

## Unresolved Questions

- Where should `RedisConfig` be constructed at runtime? `device_fp::config::RedisStoreConfig` only exposes `url` + `key_prefix`; the runtime needs ttl/window/op_timeout/breaker_threshold. Suggest extending `RedisStoreConfig` in a follow-up — out of scope for this phase since detector-wiring lives in phase-09.
- testcontainers vs env-var for CI — defer to ops preference.
