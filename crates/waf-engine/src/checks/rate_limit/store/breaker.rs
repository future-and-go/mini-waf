//! FR-004 phase-07 — `BreakerStore` composes Redis + Memory.
//!
//! Routing:
//! - `redis.breaker_open()` ⇒ short-circuit to memory (skip Redis call)
//! - else try Redis; on error fall through to memory
//!
//! The Redis store's own breaker counter advances on each failure; once it
//! crosses the configured threshold this wrapper stops attempting Redis at
//! all until the underlying store records a success and resets.
//!
//! Gated behind `feature = "redis-store"` because `RedisStore` is too.

use std::sync::Arc;

use async_trait::async_trait;

use super::redis::RedisStore;
use super::{Decision, LimitCfg, MemoryStore, RateLimitStore};

/// Wraps a Redis store and a Memory fallback. Same contract as either.
pub struct BreakerStore {
    redis: Arc<RedisStore>,
    memory: Arc<MemoryStore>,
}

impl BreakerStore {
    #[must_use]
    pub const fn new(redis: Arc<RedisStore>, memory: Arc<MemoryStore>) -> Self {
        Self { redis, memory }
    }
}

#[async_trait]
impl RateLimitStore for BreakerStore {
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        if self.redis.breaker_open() {
            return self.memory.check_and_consume(key, cfg, now_ms).await;
        }
        match self.redis.check_and_consume(key, cfg, now_ms).await {
            Ok(d) => Ok(d),
            Err(e) => {
                tracing::debug!(error = %e, "rate_limit breaker: redis failed, falling through to memory");
                self.memory.check_and_consume(key, cfg, now_ms).await
            }
        }
    }

    /// Memory-only purge — Redis relies on native `EXPIRE`.
    async fn purge_expired(&self) -> anyhow::Result<usize> {
        self.memory.purge_expired().await
    }
}
