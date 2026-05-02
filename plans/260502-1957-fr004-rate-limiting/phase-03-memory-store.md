# Phase 03 — MemoryStore (DashMap-backed)

**Priority:** P0 | **Status:** complete | **Depends:** 02
**Pattern reference:** `crates/waf-engine/src/checks/cc.rs` (TTL/eviction logic to reuse)

## Goal

`RateLimitStore` impl backed by `DashMap`. Default backend, used for standalone deployments AND as Redis fallback when breaker open.

## Requirements

- One DashMap entry per key holds **packed** `(TokenBucketState, SlidingWindowState)` — single lock, ~32B
- Reuse `cc.rs` constants: `MAX_ENTRIES = 100_000`, `ENTRY_TTL = 10 min`, `CLEANUP_INTERVAL = 1 min`
- Background cleanup task spawned on construct (graceful no-op when no Tokio runtime)
- No `.unwrap()` in production paths
- Thread-safe — must support concurrent calls per key without races

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/store/memory.rs`

**Modify:**
- `crates/waf-engine/src/checks/rate_limit/store/mod.rs` — `pub mod memory; pub use memory::MemoryStore;`

## Implementation Sketch

```rust
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dashmap::DashMap;

use crate::checks::rate_limit::algo::{SlidingWindowState, TokenBucketState};
use crate::checks::rate_limit::store::{Decision, LimitCfg, RateLimitStore};

const MAX_ENTRIES: usize = 100_000;
const ENTRY_TTL: Duration = Duration::from_secs(600);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

struct Entry {
    tb: TokenBucketState,
    sw: SlidingWindowState,
    last_touch_ms: i64,
}

pub struct MemoryStore {
    map: Arc<DashMap<String, Entry>>,
}

impl MemoryStore {
    pub fn new() -> Self { /* spawn cleanup if runtime present */ }
    fn cleanup(map: &DashMap<String, Entry>, now_ms: i64) { /* TTL + cap */ }
}

#[async_trait]
impl RateLimitStore for MemoryStore {
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        let mut entry = self.map.entry(key.to_string()).or_insert_with(|| Entry {
            tb: TokenBucketState::new_full(cfg, now_ms),
            sw: SlidingWindowState::new(now_ms, cfg.window_secs),
            last_touch_ms: now_ms,
        });
        entry.last_touch_ms = now_ms;
        if !entry.tb.try_consume(cfg, now_ms) { return Ok(Decision::BurstExceeded); }
        if !entry.sw.try_consume(cfg, now_ms) { return Ok(Decision::SustainedExceeded); }
        Ok(Decision::Allow)
    }
    async fn purge_expired(&self) -> anyhow::Result<usize> { /* manual cleanup hook */ }
}
```

## Critical Details

- `DashMap::entry().or_insert_with()` holds shard write-lock — atomic per key, no race
- TB checked **before** SW so a burst attacker sees `BurstExceeded` not `SustainedExceeded`
- Both consume on Allow; TB consumes even if SW would block (already incremented before SW check) → if this matters, swap order: check SW first without consuming, then TB, then commit. **Decision: keep simple; minor over-decrement on SW reject is fine, the request is blocked anyway.**

## Tests

- Concurrent 1000-task hammer on same key → no panics, count bounded
- TTL eviction: insert key, advance simulated time, call cleanup → entry gone
- MAX_ENTRIES enforcement: insert 100_001 keys → oldest evicted

## Verify

```bash
cargo test -p waf-engine rate_limit::store::memory
cargo clippy -p waf-engine -- -D warnings
```

## Done When

- [x] `MemoryStore` passes its own unit tests
- [x] Cleanup task spawn does not panic without runtime (test with `tokio::runtime::Handle::try_current().is_err()` path)
- [x] No `.unwrap()` outside tests
