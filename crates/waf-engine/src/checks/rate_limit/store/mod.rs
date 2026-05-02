//! `RateLimitStore` trait and shared value types.
//!
//! Backends (in-memory, Redis, …) implement this trait. The pipeline
//! consumes only the trait — no backend knowledge leaks upward.

use async_trait::async_trait;

pub mod memory;
pub use memory::MemoryStore;

/// Outcome of a single `check_and_consume` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    /// Request is within both burst and sustained limits.
    Allow,
    /// Token bucket is empty — short-term burst limit hit.
    BurstExceeded,
    /// Sliding window count exceeded `window_limit` for `window_secs`.
    SustainedExceeded,
}

/// Per-key rate-limit configuration (burst + sustained window).
#[derive(Clone, Debug)]
pub struct LimitCfg {
    /// Maximum tokens the bucket can hold (peak burst size).
    pub burst_capacity: u32,
    /// Tokens added per second (steady-state rate).
    pub burst_refill_per_s: f64,
    /// Sliding-window length in seconds.
    pub window_secs: u32,
    /// Maximum requests allowed within `window_secs`.
    pub window_limit: u32,
}

/// Atomic rate-limit operations on a keyed counter.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Atomically refill the token bucket, consume one token, and update the
    /// sliding window. Returns the resulting decision.
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision>;

    /// Sweep idle entries. Returns count purged. (No-op for backends that
    /// rely on native TTL such as Redis `EXPIRE`.)
    async fn purge_expired(&self) -> anyhow::Result<usize>;
}
