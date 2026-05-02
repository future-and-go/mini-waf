//! Redis-backed `IdentityStore` (feature `redis-store`).
//!
//! Storage scheme (all keys prefixed by `cfg.key_prefix`, default `wafp:`):
//! - `wafp:fp:{h}`  HASH  fields: `first_seen`, `last_seen`
//! - `wafp:ips:{h}` ZSET  score=ts, member=ip string  (sliding window)
//! - `wafp:uas:{h}` ZSET  score=ts, member=hex(hash(ua))
//!
//! `observe` runs as a single atomic Lua script — one round-trip — and
//! returns the post-insert window cardinalities + first/last seen.
//! `purge_expired` SCANs `fp:*` keys, deletes any whose `last_seen` is
//! older than `now - ttl_secs`. Wall-clock TTL via `EXPIRE` is also set
//! on every write so abandoned keys eventually disappear without a sweep.
//!
//! All Redis ops wrap in `tokio::time::timeout`; consecutive failures
//! advance an `AtomicU32` breaker counter — callers can check
//! `breaker_open()` and degrade to the memory store.

use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use ahash::RandomState;
use anyhow::{Context, anyhow};
use async_trait::async_trait;
use redis::{AsyncCommands, Script, aio::ConnectionManager};
use tokio::time::timeout;

use crate::device_fp::identity::identity_trait::IdentityStore;
use crate::device_fp::types::{FpKey, IdentityRecord, Observation};

#[derive(Clone, Debug)]
pub struct RedisConfig {
    pub url: String,
    pub key_prefix: String,
    pub ttl_secs: u32,
    pub window_secs: u32,
    pub op_timeout: Duration,
    pub breaker_threshold: u32,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: "redis://127.0.0.1:6379".into(),
            key_prefix: "wafp:".into(),
            ttl_secs: 3600,
            window_secs: 600,
            op_timeout: Duration::from_millis(50),
            breaker_threshold: 5,
        }
    }
}

/// One round-trip atomic observe. Returns `[ip_count, ua_count, first_seen, last_seen]`.
const OBSERVE_LUA: &str = r"
local ts = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local ttl = tonumber(ARGV[5])
redis.call('ZADD', KEYS[2], ts, ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', '('..cutoff)
local ip_n = redis.call('ZCARD', KEYS[2])
redis.call('ZADD', KEYS[3], ts, ARGV[4])
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', '('..cutoff)
local ua_n = redis.call('ZCARD', KEYS[3])
local fs = redis.call('HGET', KEYS[1], 'first_seen')
if (not fs) or tonumber(fs) > ts then
  redis.call('HSET', KEYS[1], 'first_seen', ts); fs = ts
end
local ls = redis.call('HGET', KEYS[1], 'last_seen')
if (not ls) or tonumber(ls) < ts then
  redis.call('HSET', KEYS[1], 'last_seen', ts); ls = ts
end
redis.call('EXPIRE', KEYS[1], ttl)
redis.call('EXPIRE', KEYS[2], ttl)
redis.call('EXPIRE', KEYS[3], ttl)
return {ip_n, ua_n, tonumber(fs), tonumber(ls)}
";

pub struct RedisIdentityStore {
    conn: ConnectionManager,
    cfg: RedisConfig,
    consecutive_fails: AtomicU32,
    hasher: RandomState,
    observe_script: Script,
}

impl std::fmt::Debug for RedisIdentityStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisIdentityStore")
            .field("cfg", &self.cfg)
            .field("consecutive_fails", &self.consecutive_fails.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl RedisIdentityStore {
    pub async fn new(cfg: RedisConfig) -> anyhow::Result<Self> {
        let client = redis::Client::open(cfg.url.as_str())
            .with_context(|| format!("device_fp redis: open client {}", cfg.url))?;
        let mut conn = ConnectionManager::new(client)
            .await
            .context("device_fp redis: connection manager init")?;
        let _: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .context("device_fp redis: ping")?;
        Ok(Self {
            conn,
            cfg,
            consecutive_fails: AtomicU32::new(0),
            hasher: RandomState::new(),
            observe_script: Script::new(OBSERVE_LUA),
        })
    }

    /// Stable hex digest of all populated fingerprint algorithms — used as
    /// the Redis key suffix. ahash is non-cryptographic but collision-resistant
    /// enough for sharding (the source `FpKey` is the source of truth).
    fn key_hash(&self, key: &FpKey) -> String {
        let mut s = String::new();
        if let Some(v) = &key.ja3 { s.push_str(v.as_str()); s.push('|'); }
        if let Some(v) = &key.ja4 { s.push_str(v.as_str()); s.push('|'); }
        if let Some(v) = &key.h2_akamai { s.push_str(v.as_str()); }
        format!("{:016x}", self.hasher.hash_one(&s))
    }

    fn k_meta(&self, h: &str) -> String { format!("{}fp:{h}", self.cfg.key_prefix) }
    fn k_ips(&self, h: &str) -> String { format!("{}ips:{h}", self.cfg.key_prefix) }
    fn k_uas(&self, h: &str) -> String { format!("{}uas:{h}", self.cfg.key_prefix) }

    fn record_ok(&self) {
        self.consecutive_fails.store(0, Ordering::Relaxed);
    }

    fn record_fail(&self) {
        let n = self.consecutive_fails.fetch_add(1, Ordering::Relaxed) + 1;
        if n == self.cfg.breaker_threshold {
            tracing::warn!(consecutive_fails = n, "device_fp redis: circuit breaker tripped");
        }
    }

    /// True once `breaker_threshold` consecutive failures have occurred.
    /// Caller can route traffic to a memory fallback while open.
    #[must_use]
    pub fn breaker_open(&self) -> bool {
        self.consecutive_fails.load(Ordering::Relaxed) >= self.cfg.breaker_threshold
    }
}

fn clamp_u16(n: i64) -> u16 {
    u16::try_from(n.max(0)).unwrap_or(u16::MAX)
}

#[async_trait]
impl IdentityStore for RedisIdentityStore {
    async fn observe(
        &self,
        key: &FpKey,
        ip: IpAddr,
        ua: &str,
        ts: i64,
    ) -> anyhow::Result<Observation> {
        let h = self.key_hash(key);
        let cutoff = ts.saturating_sub(i64::from(self.cfg.window_secs));
        let ua_hash = format!("{:016x}", self.hasher.hash_one(ua));
        let ip_str = ip.to_string();
        let mut conn = self.conn.clone();

        let mut invocation = self.observe_script.prepare_invoke();
        invocation
            .key(self.k_meta(&h))
            .key(self.k_ips(&h))
            .key(self.k_uas(&h))
            .arg(ts)
            .arg(cutoff)
            .arg(ip_str)
            .arg(ua_hash)
            .arg(i64::from(self.cfg.ttl_secs));

        let res = timeout(self.cfg.op_timeout, invocation.invoke_async::<(i64, i64, i64, i64)>(&mut conn)).await;
        match res {
            Ok(Ok((ip_n, ua_n, first_seen, last_seen))) => {
                self.record_ok();
                Ok(Observation {
                    distinct_ips_in_window: clamp_u16(ip_n),
                    distinct_uas_in_window: clamp_u16(ua_n),
                    first_seen_unix: first_seen,
                    last_seen_unix: last_seen,
                })
            }
            Ok(Err(e)) => { self.record_fail(); Err(anyhow!(e).context("device_fp redis: observe")) }
            Err(_) => { self.record_fail(); Err(anyhow!("device_fp redis: observe timeout {:?}", self.cfg.op_timeout)) }
        }
    }

    async fn lookup(&self, key: &FpKey) -> anyhow::Result<Option<IdentityRecord>> {
        let h = self.key_hash(key);
        let k_meta = self.k_meta(&h);
        let k_ips = self.k_ips(&h);
        let k_uas = self.k_uas(&h);
        let mut conn = self.conn.clone();

        let fut = async {
            let mut pipe = redis::pipe();
            pipe.hget(&k_meta, "first_seen")
                .hget(&k_meta, "last_seen")
                .zcard(&k_ips)
                .zcard(&k_uas);
            let res: (Option<i64>, Option<i64>, i64, i64) = pipe.query_async(&mut conn).await?;
            Ok::<_, redis::RedisError>(res)
        };

        match timeout(self.cfg.op_timeout, fut).await {
            Ok(Ok((Some(first), Some(last), ip_n, ua_n))) => {
                self.record_ok();
                Ok(Some(IdentityRecord {
                    key: key.clone(),
                    first_seen_unix: first,
                    last_seen_unix: last,
                    distinct_ips: clamp_u16(ip_n),
                    distinct_uas: clamp_u16(ua_n),
                }))
            }
            Ok(Ok(_)) => { self.record_ok(); Ok(None) }
            Ok(Err(e)) => { self.record_fail(); Err(anyhow!(e).context("device_fp redis: lookup")) }
            Err(_) => { self.record_fail(); Err(anyhow!("device_fp redis: lookup timeout {:?}", self.cfg.op_timeout)) }
        }
    }

    /// Scan-based purge: walk `fp:*` keys, delete trios whose `last_seen`
    /// is older than `now - ttl_secs`. SCAN is O(N) over the keyspace but
    /// bounded by `ttl_secs` cadence — Redis-side `EXPIRE` is the primary
    /// reaper; this exists to honour the trait contract under any clock.
    async fn purge_expired(&self) -> anyhow::Result<usize> {
        let now = chrono::Utc::now().timestamp();
        let cutoff = now.saturating_sub(i64::from(self.cfg.ttl_secs));
        let pattern = format!("{}fp:*", self.cfg.key_prefix);
        let prefix_len = self.cfg.key_prefix.len() + "fp:".len();
        let mut conn = self.conn.clone();

        let mut purged = 0_usize;

        let scan_fut = async {
            let mut iter = conn.scan_match::<_, String>(pattern.clone()).await?;
            let mut keys: Vec<String> = Vec::new();
            while let Some(k) = iter.next_item().await {
                keys.push(k);
            }
            Ok::<_, redis::RedisError>(keys)
        };
        let keys = match timeout(self.cfg.op_timeout * 4, scan_fut).await {
            Ok(Ok(k)) => { self.record_ok(); k }
            Ok(Err(e)) => { self.record_fail(); return Err(anyhow!(e).context("device_fp redis: purge scan")); }
            Err(_) => { self.record_fail(); return Err(anyhow!("device_fp redis: purge scan timeout")); }
        };

        let mut conn = self.conn.clone();
        for fp_key in keys {
            let last_seen: Option<i64> = match timeout(
                self.cfg.op_timeout,
                conn.hget::<_, _, Option<i64>>(&fp_key, "last_seen"),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(_)) | Err(_) => continue,
            };
            let Some(ls) = last_seen else { continue };
            if ls >= cutoff { continue; }
            // Strip the `<prefix>fp:` head to reconstruct sibling keys.
            let suffix = &fp_key[prefix_len..];
            let ips = format!("{}ips:{suffix}", self.cfg.key_prefix);
            let uas = format!("{}uas:{suffix}", self.cfg.key_prefix);
            let mut pipe = redis::pipe();
            pipe.del(&fp_key).del(&ips).del(&uas);
            if timeout(self.cfg.op_timeout, pipe.query_async::<()>(&mut conn))
                .await
                .is_ok()
            {
                purged += 1;
            }
        }
        Ok(purged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_fp::identity::conformance::run_store_conformance;
    use std::sync::Arc;

    /// Conformance suite — runs only when `REDIS_TEST_URL` is set (e.g.
    /// `redis://127.0.0.1:6379`). Skipped otherwise so default `cargo test
    /// --features redis-store` stays hermetic.
    #[tokio::test]
    async fn conformance_suite_against_real_redis() {
        let Ok(url) = std::env::var("REDIS_TEST_URL") else {
            tracing::info!("skipping: REDIS_TEST_URL unset");
            return;
        };
        // Per-run unique key_prefix avoids clobber across reruns.
        let prefix = format!("wafp_test_{}:", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0));
        let store = RedisIdentityStore::new(RedisConfig {
            url,
            key_prefix: prefix,
            ttl_secs: 3600,
            window_secs: 600,
            op_timeout: Duration::from_millis(500),
            breaker_threshold: 5,
        })
        .await
        .expect("connect to REDIS_TEST_URL");
        let arc: Arc<dyn IdentityStore> = Arc::new(store);
        run_store_conformance(arc).await;
    }
}
