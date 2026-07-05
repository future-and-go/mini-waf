# 2026-07-05 — GH-201: redis fail-mode policy (implementation)

## What

A Redis outage silently faked health: `RedisRiskStore::apply` swallowed
errors/timeouts and returned a cache-hit or fresh zero state with no signal,
and `read` fabricated `Ok(cached)` on failure. `TierPolicy.fail_mode` was
never consulted — a fail-closed tier stayed wide open during an outage.

Three-part fix:

- **Store signaling** (`store_trait.rs`, `redis.rs`, `memory.rs`):
  `ApplyResult` gains `degraded: bool`. The redis error/timeout arms return
  the best-known substitute (last cached state, else fresh zero state) via
  `degraded_substitute`, always flagged `degraded: true`. `read` now returns
  the error faithfully (it is advisory — no production callers; verified by
  grep). Memory store always sets `degraded: false`.
- **Policy** (`threshold.rs`): pure `degraded_action(fail_mode, score,
  thresholds, override_block)` — `Open` → normal `decide` on the best-known
  score (a cached high score still defends), `Close` → `Block { 503, None }`
  (parity with the DDoS degrade path).
- **Scorer wiring** (`scorer.rs`): `score_with_l2` branches on
  `result.degraded`, logs `warn!(target: "risk::degrade", ...)` with client
  IP, fail mode, and score, then routes through `degraded_action`.

The plan's optional breaker fast-fail short-circuit was deliberately dropped:
short-circuiting at the top of `apply` would prevent `record_ok` from ever
firing after Redis recovers, latching the breaker open permanently.

## How it was verified

- Pure unit tests for `degraded_substitute` (cached score survives, fresh
  state flagged) and exhaustive `degraded_action` band tests (Open across
  allow/challenge/block/pinned; Close always 503).
- Deterministic mock-store acceptance tests in scorer tests (`DegradedStore`
  whose `apply` always returns `degraded: true`): Open + score 0 → Allow;
  Open + cached 95 → Block 403 (no score reset); Close + score 0 → Block 503;
  healthy `MemoryRiskStore` + Close tier → Allow (fail_mode only applies
  during degradation). The 503 assertion can only come from the new path —
  `decide` never emits 503.
- `REDIS_TEST_URL`-gated test drives the real timeout arm (1ns `op_timeout`
  against a live server) → `degraded: true` + `read` → `Err`.
- `cargo test -p waf-engine --lib --features redis-store "risk::"`: 260
  passed, 0 failed (docker-gated `engine::tests` set excluded as
  pre-established). Existing `redis_failover` suite unchanged and green.
- `cargo clippy --all-targets --features redis-store` clean;
  `cargo fmt --all --check` clean.

## Gotchas

- `RedisRiskStore::new` PINGs on construction, so an unreachable-URL store
  cannot be built in the default test suite — that is why the degraded logic
  is factored into the pure `degraded_substitute` free function and the
  outage test is REDIS_TEST_URL-gated instead.
- The redis store module is behind the `redis-store` cargo feature; a bare
  `cargo test risk::store` silently skips it (13 vs 21 tests).
- clippy pedantic `similar_names` fires on `store`/`score` bindings in the
  same fn.
