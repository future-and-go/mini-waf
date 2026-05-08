//! Consumed-nonce store for challenge credit replay prevention.
//!
//! Two-tier design:
//! 1. In-process LRU cache (~100k entries, ~5MB) — fast path
//! 2. Redis SETNX — cluster-wide source of truth
//!
//! A nonce is "consumed" when a valid token is verified. Replay attempts
//! return false from `try_consume`.

use std::collections::{HashMap, VecDeque};
#[cfg(feature = "redis-store")]
use std::time::Duration;

use parking_lot::Mutex;

/// LRU cache for consumed nonces. Not thread-safe; wrap in Mutex.
struct LruCache {
    entries: HashMap<String, ()>,
    order: VecDeque<String>,
    capacity: usize,
}

impl LruCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Check if nonce exists in cache.
    fn contains(&self, nonce: &str) -> bool {
        self.entries.contains_key(nonce)
    }

    /// Insert nonce into cache, evicting oldest if at capacity.
    /// Returns true if newly inserted, false if already present.
    fn insert(&mut self, nonce: String) -> bool {
        if self.entries.contains_key(&nonce) {
            return false;
        }

        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }

        self.order.push_back(nonce.clone());
        self.entries.insert(nonce, ());
        true
    }
}

/// Result of trying to consume a nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsumeResult {
    /// Nonce consumed successfully (first use).
    Consumed,
    /// Nonce already consumed (replay).
    Replay,
    /// Redis operation failed, but LRU says first use — proceed with caution.
    ConsumedWithWarning,
}

/// Nonce store with LRU cache and optional Redis backend.
pub struct NonceStore {
    lru: Mutex<LruCache>,
    #[cfg(feature = "redis-store")]
    redis: Option<NonceRedisBackend>,
    #[cfg(feature = "redis-store")]
    key_prefix: String,
    #[cfg(feature = "redis-store")]
    ttl_secs: u32,
}

/// Redis backend for cluster-wide nonce tracking.
#[cfg(feature = "redis-store")]
pub struct NonceRedisBackend {
    conn: redis::aio::ConnectionManager,
    op_timeout: Duration,
}

#[cfg(feature = "redis-store")]
impl NonceRedisBackend {
    /// Create a new Redis backend from an existing connection manager.
    #[must_use]
    pub fn new(conn: redis::aio::ConnectionManager, op_timeout: Duration) -> Self {
        Self { conn, op_timeout }
    }
}

impl NonceStore {
    /// Create a new nonce store with in-memory LRU only.
    #[must_use]
    #[allow(unused_variables)] // ttl_secs used only with redis-store feature
    pub fn new(capacity: usize, ttl_secs: u32) -> Self {
        Self {
            lru: Mutex::new(LruCache::new(capacity)),
            #[cfg(feature = "redis-store")]
            redis: None,
            #[cfg(feature = "redis-store")]
            key_prefix: "waf:risk:cnonce:".into(),
            #[cfg(feature = "redis-store")]
            ttl_secs,
        }
    }

    /// Create a nonce store with Redis backend for cluster-wide tracking.
    #[cfg(feature = "redis-store")]
    #[must_use]
    pub fn with_redis(capacity: usize, ttl_secs: u32, redis: NonceRedisBackend) -> Self {
        Self {
            lru: Mutex::new(LruCache::new(capacity)),
            redis: Some(redis),
            key_prefix: "waf:risk:cnonce:".into(),
            ttl_secs,
        }
    }

    /// Try to consume a nonce. Returns `Consumed` on first use, `Replay` on repeat.
    ///
    /// Flow:
    /// 1. Check LRU cache — if present, return Replay immediately
    /// 2. Try Redis SETNX — if fails (key exists), return Replay
    /// 3. Insert into LRU and return Consumed
    pub async fn try_consume(&self, nonce: &str) -> ConsumeResult {
        // Redis path (if enabled) — Redis SETNX is authoritative for cluster-wide dedup
        #[cfg(feature = "redis-store")]
        if let Some(ref redis) = self.redis {
            // Fast path: check LRU first (avoids Redis roundtrip for obvious replays)
            if self.lru.lock().contains(nonce) {
                return ConsumeResult::Replay;
            }

            match self.redis_setnx(redis, nonce).await {
                Ok(true) => {
                    // Successfully set in Redis — consume in LRU too
                    self.lru.lock().insert(nonce.to_string());
                    return ConsumeResult::Consumed;
                }
                Ok(false) => {
                    // Key already exists in Redis — replay
                    return ConsumeResult::Replay;
                }
                Err(e) => {
                    // Redis failed — fallback to atomic LRU check-and-insert
                    tracing::warn!(error = %e, nonce = %nonce, "nonce redis SETNX failed, using LRU fallback");
                    let mut lru = self.lru.lock();
                    if lru.contains(nonce) {
                        return ConsumeResult::Replay;
                    }
                    lru.insert(nonce.to_string());
                    return ConsumeResult::ConsumedWithWarning;
                }
            }
        }

        // No Redis — atomic LRU check-and-insert to prevent TOCTOU race
        let mut lru = self.lru.lock();
        if lru.contains(nonce) {
            return ConsumeResult::Replay;
        }
        lru.insert(nonce.to_string());
        ConsumeResult::Consumed
    }

    /// Redis SETNX with TTL.
    #[cfg(feature = "redis-store")]
    async fn redis_setnx(&self, redis: &NonceRedisBackend, nonce: &str) -> anyhow::Result<bool> {
        use tokio::time::timeout;

        let key = format!("{}{}", self.key_prefix, nonce);
        // TTL = token TTL + 10s skew margin
        let ttl = self.ttl_secs.saturating_add(10);

        let mut conn = redis.conn.clone();
        let fut = async {
            // SET key "1" NX EX ttl — returns Ok("OK") if set, Nil if exists
            let result: Option<String> = redis::cmd("SET")
                .arg(&key)
                .arg("1")
                .arg("NX")
                .arg("EX")
                .arg(ttl)
                .query_async(&mut conn)
                .await?;
            Ok::<_, redis::RedisError>(result.is_some())
        };

        match timeout(redis.op_timeout, fut).await {
            Ok(Ok(set)) => Ok(set),
            Ok(Err(e)) => Err(anyhow::anyhow!(e).context("nonce redis SETNX")),
            Err(_) => Err(anyhow::anyhow!("nonce redis SETNX timeout")),
        }
    }

    /// Check if a nonce has been consumed (without consuming it).
    #[must_use]
    pub fn is_consumed(&self, nonce: &str) -> bool {
        self.lru.lock().contains(nonce)
    }

    /// Get current LRU cache size.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lru.lock().entries.len()
    }

    /// Check if LRU cache is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn consume_once_returns_consumed() {
        let store = NonceStore::new(100, 300);
        let result = store.try_consume("nonce-1").await;
        assert_eq!(result, ConsumeResult::Consumed);
    }

    #[tokio::test]
    async fn consume_twice_returns_replay() {
        let store = NonceStore::new(100, 300);

        let first = store.try_consume("nonce-1").await;
        assert_eq!(first, ConsumeResult::Consumed);

        let second = store.try_consume("nonce-1").await;
        assert_eq!(second, ConsumeResult::Replay);
    }

    #[tokio::test]
    async fn different_nonces_both_consumed() {
        let store = NonceStore::new(100, 300);

        let a = store.try_consume("nonce-a").await;
        let b = store.try_consume("nonce-b").await;

        assert_eq!(a, ConsumeResult::Consumed);
        assert_eq!(b, ConsumeResult::Consumed);
    }

    #[tokio::test]
    async fn lru_evicts_oldest() {
        let store = NonceStore::new(3, 300);

        store.try_consume("n1").await;
        store.try_consume("n2").await;
        store.try_consume("n3").await;
        assert_eq!(store.len(), 3);

        // Insert 4th — should evict n1
        store.try_consume("n4").await;
        assert_eq!(store.len(), 3);

        // n1 should no longer be in cache (could be replayed if Redis absent)
        assert!(!store.is_consumed("n1"));
        assert!(store.is_consumed("n4"));
    }

    #[test]
    fn is_consumed_without_consuming() {
        let store = NonceStore::new(100, 300);
        assert!(!store.is_consumed("test"));

        // Manually insert via LRU
        store.lru.lock().insert("test".into());
        assert!(store.is_consumed("test"));
    }
}
