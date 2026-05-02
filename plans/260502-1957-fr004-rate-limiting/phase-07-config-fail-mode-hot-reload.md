# Phase 07 — Config (YAML), Hot-Reload, Breaker Wrapper

**Priority:** P0 | **Status:** in-progress | **Depends:** 04
**Related FRs:** FR-021 (hot-reload), FR-023 (scoping), FR-036/037/038 (fail-mode per tier)

## Goal

Externalise rate-limit config to a **YAML** file (`configs/rate-limit.yaml`), support hot-reload (no restart), and add `BreakerStore` wrapper composing Redis + Memory. Mirrors existing `device-fp.yaml` pattern.

## Design Decisions (deviate from initial draft)

1. **YAML not TOML** — operator-facing config lives in `configs/rate-limit.yaml`, mirroring `configs/device-fp.yaml`. The main `default.toml` only holds an optional path reference (`[rate_limit] config_path = "configs/rate-limit.yaml"`). This keeps the runtime dial well-trodden by the device-fp prior art (schema versioning, `deny_unknown_fields`, `notify`-based watcher).
2. **`fail_mode` lives on `TierPolicy`, not duplicated** — `check.rs` already reads `ctx.tier_policy.fail_mode` (FR-037 implemented). Adding a duplicate `fail_mode` to the rate-limit YAML would create two sources of truth. **Skip the duplicate.** Operator changes fail-mode by editing the tier classifier config.
3. **Schema versioning** — `schema_version: 1` at the YAML root; bumped only on breaking changes.
4. **`BreakerStore` gated on `feature = "redis-store"`** — same as `RedisStore`.

## Requirements

- YAML file `configs/rate-limit.yaml` with schema_version, enabled, session_cookie, tiers map, optional redis block
- Per-tier `LimitCfg` keyed by `Tier { critical, high, medium, catch_all }` (snake_case in YAML)
- `session_cookie: String` (default: `"SESSIONID"`)
- Optional `redis:` block — absence = standalone (memory only)
- Hot-reload: `notify`-based file watcher → `Arc<ArcSwap<RateLimitConfig>>` swap; bad edits log warn + retain previous snapshot
- `BreakerStore`: holds `Arc<RedisStore>` + `Arc<MemoryStore>`; routes via `breaker_open()` and falls through on error

## Files

**Create:**
- `crates/waf-engine/src/checks/rate_limit/config.rs` — YAML schema (DTOs) + `from_yaml_str` / `from_path` / `validate` + `Into<RateLimitConfig>`
- `crates/waf-engine/src/checks/rate_limit/reload.rs` — `RateLimitReloader` mirroring `device_fp::reload`
- `crates/waf-engine/src/checks/rate_limit/store/breaker.rs` — `BreakerStore`
- `configs/rate-limit.yaml` — default sample config

**Modify:**
- `crates/waf-engine/src/checks/rate_limit/mod.rs` — declare new modules + re-export
- `crates/waf-engine/src/checks/rate_limit/check.rs` — accept `Arc<ArcSwap<RateLimitConfig>>` instead of `Arc<RateLimitConfig>`
- `crates/waf-engine/src/checks/rate_limit/store/mod.rs` — gated re-export of `BreakerStore`
- `crates/waf-common/src/config.rs` — add `RateLimitFileRef { config_path: Option<String> }` field on `AppConfig`
- `crates/waf-engine/src/engine.rs` — store `Arc<ArcSwap<RateLimitConfig>>` + `start_rate_limit_watcher` method

## YAML Sketch (`configs/rate-limit.yaml`)

```yaml
# FR-004 rate-limiting — default configuration.
# Schema v1. Empty / absent file ⇒ subsystem inert.
# Hot-reload watches this file; bad edits log a warning and the
# previous snapshot is retained.

rate_limit:
  schema_version: 1
  enabled: true
  session_cookie: SESSIONID
  hot_reload: true

  tiers:
    critical:
      burst_capacity: 5
      burst_refill_per_s: 2.0
      window_secs: 60
      window_limit: 30
    high:
      burst_capacity: 20
      burst_refill_per_s: 10.0
      window_secs: 60
      window_limit: 200
    medium:
      burst_capacity: 50
      burst_refill_per_s: 20.0
      window_secs: 60
      window_limit: 600
    catch_all:
      burst_capacity: 100
      burst_refill_per_s: 50.0
      window_secs: 60
      window_limit: 1500

  # Omit the `redis:` block for standalone (memory-only) mode.
  redis:
    url: "redis://127.0.0.1:6379"
    key_prefix: "wafrl:"
    op_timeout_ms: 50
    breaker_threshold: 5
```

## TOML Reference (in `default.toml`)

```toml
[rate_limit]
config_path = "configs/rate-limit.yaml"   # omit ⇒ subsystem inert
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

- YAML round-trip parse for full + redis-omitted variants
- Bad YAML rejected with descriptive error (unknown field, bad enum, schema mismatch)
- Hot-reload: write file → watcher picks up → `ArcSwap` swap → next call sees new limits
- `BreakerStore`: breaker open → uses memory; redis err mid-flight → falls through to memory
- Per-tier resolution: Critical request uses critical limits, CatchAll uses catch_all

## Verify

```bash
cargo test -p waf-engine rate_limit
cargo build --release
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Done When

- [x] YAML parses standalone + redis variants
- [x] Hot-reload swaps `ArcSwap` without dropping in-flight requests; bad edits keep previous snapshot
- [x] BreakerStore routes correctly; falls through after `breaker_threshold` failures
- [x] Tier fail-mode honored on store error (already in check.rs via `TierPolicy`)
