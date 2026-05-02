# Phase 06 — RedisStore (cluster mode)

**Priority:** P0 | **Status:** pending | **Depends:** 05
**Pattern reference:** `crates/waf-engine/src/device_fp/identity/redis.rs`

## Goal

`RateLimitStore` impl backed by Redis. Single Lua-script round-trip per request. Circuit breaker + op_timeout. Behind `redis-store` feature flag.

## Requirements

- Single Lua script: refill TB → consume → roll SW → consume SW → return decision code (atomic)
- `op_timeout` default 50ms
- `consecutive_fails: AtomicU32` + `breaker_threshold` (default 5) + `breaker_open()` reader
- `EXPIRE` set on every write (TTL ≈ window_secs * 4) so abandoned keys self-purge
- `RedisConfig`: `url, key_prefix ("wafrl:"), op_timeout, breaker_threshold`

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/store/redis.rs`

**Modify:**
- `crates/waf-engine/src/checks/rate_limit/store/mod.rs` — `#[cfg(feature = "redis-store")] pub mod redis;`
- `crates/waf-engine/Cargo.toml` — add `redis-store` feature gating the same `redis = { ... }` dep already pulled by device_fp

## Lua Script (sketch)

Single key per request, encoded as HASH at `wafrl:{key}` with fields `tb_tokens, tb_last_ms, sw_curr, sw_prev, sw_win_start_ms`.

```lua
-- ARGV: now_ms, burst_capacity, burst_refill_per_s_e3, win_secs, win_limit, ttl_secs
-- KEYS: hkey
local h = KEYS[1]
local now = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local refill_e3 = tonumber(ARGV[3])  -- refill_per_s * 1000 (avoid float ARGV)
local win_s = tonumber(ARGV[4])
local lim = tonumber(ARGV[5])
local ttl = tonumber(ARGV[6])

local v = redis.call('HMGET', h, 'tb_tokens', 'tb_last_ms', 'sw_curr', 'sw_prev', 'sw_win_start_ms')
local tb_tokens = tonumber(v[1]) or cap
local tb_last_ms = tonumber(v[2]) or now
local sw_curr = tonumber(v[3]) or 0
local sw_prev = tonumber(v[4]) or 0
local win_ms = win_s * 1000
local sw_start = tonumber(v[5]) or (math.floor(now / win_ms) * win_ms)

-- TB refill
local elapsed_s = math.max(0, now - tb_last_ms) / 1000.0
tb_tokens = math.min(cap, tb_tokens + elapsed_s * (refill_e3 / 1000.0))
if tb_tokens < 1.0 then
  redis.call('HMSET', h, 'tb_tokens', tb_tokens, 'tb_last_ms', now)
  redis.call('EXPIRE', h, ttl)
  return 1  -- BurstExceeded
end
tb_tokens = tb_tokens - 1

-- SW roll
local bucket_now = math.floor(now / win_ms) * win_ms
local advance = math.floor((bucket_now - sw_start) / win_ms)
if advance == 1 then sw_prev = sw_curr; sw_curr = 0; sw_start = bucket_now
elseif advance >= 2 then sw_prev = 0; sw_curr = 0; sw_start = bucket_now end

local elapsed_in_curr = now - sw_start
local weight_prev = 1.0 - math.min(1.0, math.max(0.0, elapsed_in_curr / win_ms))
local estimated = sw_curr + sw_prev * weight_prev
if (estimated + 1) > lim then
  redis.call('HMSET', h, 'tb_tokens', tb_tokens, 'tb_last_ms', now,
                       'sw_curr', sw_curr, 'sw_prev', sw_prev, 'sw_win_start_ms', sw_start)
  redis.call('EXPIRE', h, ttl)
  return 2  -- SustainedExceeded
end
sw_curr = sw_curr + 1
redis.call('HMSET', h, 'tb_tokens', tb_tokens, 'tb_last_ms', now,
                     'sw_curr', sw_curr, 'sw_prev', sw_prev, 'sw_win_start_ms', sw_start)
redis.call('EXPIRE', h, ttl)
return 0  -- Allow
```

## Implementation Sketch

```rust
pub struct RedisStore {
    conn: ConnectionManager,
    cfg: RedisConfig,
    consecutive_fails: AtomicU32,
    script: Script,
}

impl RedisStore {
    pub fn breaker_open(&self) -> bool {
        self.consecutive_fails.load(Ordering::Relaxed) >= self.cfg.breaker_threshold
    }
    fn record_success(&self) { self.consecutive_fails.store(0, Ordering::Relaxed); }
    fn record_failure(&self) { self.consecutive_fails.fetch_add(1, Ordering::Relaxed); }
}

#[async_trait]
impl RateLimitStore for RedisStore {
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        let hkey = format!("{}{}", self.cfg.key_prefix, key);
        let ttl = (cfg.window_secs as i64 * 4).max(60);
        let invocation = self.script
            .key(&hkey)
            .arg(now_ms)
            .arg(cfg.burst_capacity)
            .arg((cfg.burst_refill_per_s * 1000.0) as i64)
            .arg(cfg.window_secs)
            .arg(cfg.window_limit)
            .arg(ttl)
            .invoke_async::<_, i64>(&mut self.conn.clone());

        match timeout(self.cfg.op_timeout, invocation).await {
            Ok(Ok(0)) => { self.record_success(); Ok(Decision::Allow) }
            Ok(Ok(1)) => { self.record_success(); Ok(Decision::BurstExceeded) }
            Ok(Ok(2)) => { self.record_success(); Ok(Decision::SustainedExceeded) }
            Ok(Ok(c)) => { self.record_failure(); Err(anyhow!("unexpected lua return {c}")) }
            Ok(Err(e)) => { self.record_failure(); Err(anyhow!("redis err: {e}")) }
            Err(_) => { self.record_failure(); Err(anyhow!("redis timeout")) }
        }
    }

    async fn purge_expired(&self) -> anyhow::Result<usize> { Ok(0) /* EXPIRE handles it */ }
}
```

## Wrapper: `BreakerStore`

Composite store that wraps `RedisStore` + `MemoryStore`. On `breaker_open()`, route to memory; on close, route to redis. Built in phase 07 (config wiring), not here.

## Tests

- Conformance suite passes when `REDIS_TEST_URL` env var present (otherwise skip with `eprintln!`)
- Inject 6 consecutive timeouts → `breaker_open()` returns true
- After single success → `consecutive_fails` resets to 0

## Verify

```bash
cargo build -p waf-engine --features redis-store
cargo clippy -p waf-engine --features redis-store -- -D warnings
REDIS_TEST_URL=redis://127.0.0.1:6379 cargo test -p waf-engine --features redis-store rate_limit
```

## Done When

- [ ] `redis-store` feature compiles
- [ ] Conformance suite green against live Redis
- [ ] Breaker opens at 5 consecutive failures, recovers on success
- [ ] No `.unwrap()` outside tests
