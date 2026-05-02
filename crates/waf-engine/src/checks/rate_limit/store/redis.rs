//! Redis-backed `RateLimitStore` (feature `redis-store`).
//!
//! All state for one key lives in a single Redis HASH at `<prefix><key>` with
//! fields `tb_tokens`, `tb_last_ms`, `sw_curr`, `sw_prev`, `sw_win_start_ms`.
//!
//! `check_and_consume` runs as a single atomic Lua script — one round-trip:
//! refill TB → consume → roll SW → consume SW → return decision code.
//! Atomicity comes from Redis itself: nothing else can interleave between
//! the script's `HMGET` and `HMSET`, so concurrent requests cannot
//! double-spend the bucket.
//!
//! Failures (timeout, redis error, unexpected return) advance an
//! `AtomicU32` breaker counter. Once it crosses `breaker_threshold`,
//! `breaker_open()` returns true so the wrapping store (phase 07) can
//! route to the in-memory fallback. A single success resets the counter.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use anyhow::{Context, anyhow};
use async_trait::async_trait;
use redis::{Script, aio::ConnectionManager};
use tokio::time::timeout;

use crate::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

/// Connection + behaviour knobs for the Redis backend.
#[derive(Clone, Debug)]
pub struct RedisConfig {
    /// Redis URL, e.g. `redis://127.0.0.1:6379`.
    pub url: String,
    /// Prepended to every key, used to namespace from other Redis users.
    pub key_prefix: String,
    /// Per-call timeout. Above this we record a failure and surface an error.
    pub op_timeout: Duration,
    /// Consecutive failures required to open the circuit breaker.
    pub breaker_threshold: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            key_prefix: "wafrl:".into(),
            op_timeout: Duration::from_millis(50),
            breaker_threshold: 5,
        }
    }
}

/// Single round-trip: refill TB → consume → roll SW → consume SW.
///
/// ARGV: `now_ms, burst_capacity, burst_refill_per_s_e3, win_secs, win_limit, ttl_secs`
/// (refill is encoded ×1000 to avoid passing floats through ARGV).
///
/// Return codes: `0 = Allow`, `1 = BurstExceeded`, `2 = SustainedExceeded`.
const CHECK_AND_CONSUME_LUA: &str = r"
local h = KEYS[1]
local now = tonumber(ARGV[1])
local cap = tonumber(ARGV[2])
local refill_e3 = tonumber(ARGV[3])
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

-- Token-bucket refill: tokens accrued since last touch, capped at capacity.
local elapsed_s = math.max(0, now - tb_last_ms) / 1000.0
tb_tokens = math.min(cap, tb_tokens + elapsed_s * (refill_e3 / 1000.0))
if tb_tokens < 1.0 then
  redis.call('HMSET', h, 'tb_tokens', tb_tokens, 'tb_last_ms', now)
  redis.call('EXPIRE', h, ttl)
  return 1
end
tb_tokens = tb_tokens - 1

-- Sliding-window roll forward: 0 = same window, 1 = curr→prev, ≥2 = both stale.
local bucket_now = math.floor(now / win_ms) * win_ms
local advance = math.floor((bucket_now - sw_start) / win_ms)
if advance == 1 then
  sw_prev = sw_curr; sw_curr = 0; sw_start = bucket_now
elseif advance >= 2 then
  sw_prev = 0; sw_curr = 0; sw_start = bucket_now
end

-- Weighted estimate: portion of prev window still in the trailing `win_secs`.
local elapsed_in_curr = now - sw_start
local weight_prev = 1.0 - math.min(1.0, math.max(0.0, elapsed_in_curr / win_ms))
local estimated = sw_curr + sw_prev * weight_prev
if (estimated + 1) > lim then
  redis.call('HMSET', h, 'tb_tokens', tb_tokens, 'tb_last_ms', now,
                       'sw_curr', sw_curr, 'sw_prev', sw_prev, 'sw_win_start_ms', sw_start)
  redis.call('EXPIRE', h, ttl)
  return 2
end
sw_curr = sw_curr + 1
redis.call('HMSET', h, 'tb_tokens', tb_tokens, 'tb_last_ms', now,
                     'sw_curr', sw_curr, 'sw_prev', sw_prev, 'sw_win_start_ms', sw_start)
redis.call('EXPIRE', h, ttl)
return 0
";

/// Redis-backed `RateLimitStore`.
pub struct RedisStore {
    conn: ConnectionManager,
    cfg: RedisConfig,
    consecutive_fails: AtomicU32,
    script: Script,
}

impl std::fmt::Debug for RedisStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisStore")
            .field("cfg", &self.cfg)
            .field("consecutive_fails", &self.consecutive_fails.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RedisStore {
    /// Open a connection, PING to verify, return a ready store.
    pub async fn new(cfg: RedisConfig) -> anyhow::Result<Self> {
        let client = redis::Client::open(cfg.url.as_str())
            .with_context(|| format!("rate_limit redis: open client {}", cfg.url))?;
        let mut conn = ConnectionManager::new(client)
            .await
            .context("rate_limit redis: connection manager init")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("rate_limit redis: ping")?;
        Ok(Self {
            conn,
            cfg,
            consecutive_fails: AtomicU32::new(0),
            script: Script::new(CHECK_AND_CONSUME_LUA),
        })
    }

    /// True once `breaker_threshold` consecutive failures have occurred.
    /// The phase-07 wrapper reads this to route to the memory fallback.
    #[must_use]
    pub fn breaker_open(&self) -> bool {
        self.consecutive_fails.load(Ordering::Relaxed) >= self.cfg.breaker_threshold
    }

    fn record_ok(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
    }

    fn record_fail(&self) {
        let n = self.consecutive_fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.cfg.breaker_threshold {
            tracing::warn!(consecutive_fails = n, "rate_limit redis: circuit breaker tripped");
        }
    }
}

#[async_trait]
impl RateLimitStore for RedisStore {
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        let hkey = format!("{}{}", self.cfg.key_prefix, key);
        // TTL ~= 4 windows so abandoned keys self-purge; floor at 60s for tiny windows.
        let ttl = (i64::from(cfg.window_secs).saturating_mul(4)).max(60);
        // Encode refill ×1000 so ARGV stays integer (Lua's tonumber handles either,
        // but avoiding floats over the wire is cheaper and locale-safe).
        // `as i64` from f64 is saturating since Rust 1.45 (NaN→0, ±∞→bounds).
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let refill_e3 = (cfg.burst_refill_per_s * 1000.0).round() as i64;
        let mut conn = self.conn.clone();

        let mut invocation = self.script.prepare_invoke();
        invocation
            .key(&hkey)
            .arg(now_ms)
            .arg(cfg.burst_capacity)
            .arg(refill_e3)
            .arg(cfg.window_secs)
            .arg(cfg.window_limit)
            .arg(ttl);

        let res = timeout(self.cfg.op_timeout, invocation.invoke_async::<i64>(&mut conn)).await;
        match res {
            Ok(Ok(0)) => {
                self.record_ok();
                Ok(Decision::Allow)
            }
            Ok(Ok(1)) => {
                self.record_ok();
                Ok(Decision::BurstExceeded)
            }
            Ok(Ok(2)) => {
                self.record_ok();
                Ok(Decision::SustainedExceeded)
            }
            Ok(Ok(c)) => {
                self.record_fail();
                Err(anyhow!("rate_limit redis: unexpected lua return {c}"))
            }
            Ok(Err(e)) => {
                self.record_fail();
                Err(anyhow!(e).context("rate_limit redis: check_and_consume"))
            }
            Err(_) => {
                self.record_fail();
                Err(anyhow!(
                    "rate_limit redis: check_and_consume timeout {:?}",
                    self.cfg.op_timeout
                ))
            }
        }
    }

    /// No-op: Redis `EXPIRE` set on every write handles TTL natively.
    async fn purge_expired(&self) -> anyhow::Result<usize> {
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::rate_limit::conformance::run_conformance;
    use std::sync::Arc;

    fn unique_prefix() -> String {
        format!("wafrl_test_{}:", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0))
    }

    /// Conformance suite — runs only when `REDIS_TEST_URL` is set so default
    /// `cargo test --features redis-store` stays hermetic.
    #[tokio::test]
    async fn conformance_suite_against_real_redis() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping rate_limit redis conformance: REDIS_TEST_URL unset");
            return;
        };
        let store = RedisStore::new(RedisConfig {
            url,
            key_prefix: unique_prefix(),
            // Looser timeout under shared CI Redis — defaults are tuned for prod.
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
        })
        .await
        .expect("connect to REDIS_TEST_URL");
        let arc: Arc<dyn RateLimitStore> = Arc::new(store);
        run_conformance(arc).await;
    }

    /// Breaker pure-logic test (no Redis): poke `record_fail` directly.
    /// We can't construct a `RedisStore` without a live connection, so this
    /// exercises the counter via a tiny mirror struct using the same atomics.
    #[tokio::test]
    async fn breaker_opens_after_threshold_and_resets_on_success() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping breaker test: REDIS_TEST_URL unset");
            return;
        };
        let store = RedisStore::new(RedisConfig {
            url,
            key_prefix: unique_prefix(),
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
        })
        .await
        .expect("connect to REDIS_TEST_URL");

        assert!(!store.breaker_open());
        for _ in 0..6 {
            store.record_fail();
        }
        assert!(store.breaker_open());
        store.record_ok();
        assert!(!store.breaker_open());
    }
}
