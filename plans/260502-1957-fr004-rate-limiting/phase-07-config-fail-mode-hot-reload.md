# Phase 07 — Config, Fail-Mode, Hot-Reload, Breaker Wrapper

**Priority:** P0 | **Status:** pending | **Depends:** 04
**Related FRs:** FR-021 (hot-reload), FR-023 (scoping), FR-036/037/038 (fail-mode per tier)

## Goal

Wire `RateLimitConfig` into `waf-common` config, expose per-tier limits + fail-mode, support hot-reload (no restart). Add `BreakerStore` wrapper composing Redis + Memory.

## Requirements

- `RateLimitConfig` in `waf-common/src/config.rs` (single source of truth, serde)
- Per-tier `LimitCfg` map keyed by `Tier { Critical, High, Medium, CatchAll }`
- `fail_mode: "close" | "open"` per tier (default: close for Critical/High, open for Medium/CatchAll)
- `session_cookie: String` (default: `"SESSIONID"`)
- Optional `redis: Option<RedisConfig>` block — absence = standalone mode (memory only)
- Hot-reload: config wrapped in `Arc<ArcSwap<RateLimitConfig>>` (or existing `RuleStore`-style channel — match existing pattern)
- `BreakerStore`: holds `Arc<RedisStore>` + `Arc<MemoryStore>`; `check_and_consume` routes via `breaker_open()`

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/store/breaker.rs`

**Modify:**
- `crates/waf-common/src/config.rs` — add `RateLimitConfig`, `RateLimitTierCfg`
- `crates/waf-engine/src/checks/rate_limit/check.rs` — read tier cfg, apply fail_mode in `handle_store_err`
- `crates/waf-engine/src/checks/rate_limit/mod.rs` — re-export `BreakerStore`
- `configs/*.toml` — add `[rate_limit]` blocks
- `crates/waf-engine/src/engine.rs` (or wherever rules hot-reload is wired) — extend reload to refresh `RateLimitConfig`

## Config Sketch

```toml
[rate_limit]
enabled = true
session_cookie = "SESSIONID"

[rate_limit.tiers.critical]
burst_capacity = 5
burst_refill_per_s = 2.0
window_secs = 60
window_limit = 30
fail_mode = "close"

[rate_limit.tiers.high]
burst_capacity = 20
burst_refill_per_s = 10.0
window_secs = 60
window_limit = 200
fail_mode = "close"

[rate_limit.tiers.medium]
burst_capacity = 50
burst_refill_per_s = 20.0
window_secs = 60
window_limit = 600
fail_mode = "open"

[rate_limit.tiers.catch_all]
burst_capacity = 100
burst_refill_per_s = 50.0
window_secs = 60
window_limit = 1500
fail_mode = "open"

[rate_limit.redis]                  # OMIT this whole block for standalone
url = "redis://127.0.0.1:6379"
key_prefix = "wafrl:"
op_timeout_ms = 50
breaker_threshold = 5
```

## BreakerStore Sketch

```rust
pub struct BreakerStore {
    redis: Arc<RedisStore>,
    memory: Arc<MemoryStore>,
}

#[async_trait]
impl RateLimitStore for BreakerStore {
    async fn check_and_consume(&self, key: &str, cfg: &LimitCfg, now_ms: i64) -> anyhow::Result<Decision> {
        if self.redis.breaker_open() {
            return self.memory.check_and_consume(key, cfg, now_ms).await;
        }
        match self.redis.check_and_consume(key, cfg, now_ms).await {
            Ok(d) => Ok(d),
            Err(_) => self.memory.check_and_consume(key, cfg, now_ms).await,  // fall through
        }
    }
    async fn purge_expired(&self) -> anyhow::Result<usize> {
        self.memory.purge_expired().await
    }
}
```

## Tests

- TOML round-trip serde for `RateLimitConfig` (full + redis-omitted variants)
- Hot-reload: swap config, assert new limits take effect on next request without restart
- BreakerStore: redis healthy → uses redis; breaker open → uses memory; redis errors mid-flight → falls through to memory
- Per-tier resolution: request to CRITICAL route uses critical limits, MEDIUM uses medium

## Verify

```bash
cargo test -p waf-engine rate_limit
cargo test -p waf-common config
cargo build --release
```

## Done When

- [ ] Config parses both standalone and cluster TOML samples
- [ ] Hot-reload swaps `Arc` without dropping in-flight requests
- [ ] BreakerStore correctly routes; integration test simulates Redis down → memory takes over within 5 errors
- [ ] Tier fail-mode honored on store error
