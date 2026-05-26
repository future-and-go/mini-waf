---
phase: 5
title: "DB Connection Resilience"
finding: F7
status: pending
priority: P2
effort: "2h"
dependencies: []
---

# Phase 5: DB Connection Resilience

## Overview

`Database::connect()` (db.rs:18-24) makes a single connection attempt with no retry, no acquire timeout, and no health monitoring. A transient network issue or slow DB startup blocks the entire WAF. Add retry with exponential backoff, acquire timeout on the pool, and a background health-check task.

## Key Insights

- Current: `PgPoolOptions::new().max_connections(n).connect(url).await?` — single attempt, no timeout on acquire (db.rs:21-24)
- `StorageError` (error.rs:4-16) has `Database(sqlx::Error)` variant but no `ConnectionFailed` variant for retry exhaustion
- sqlx PgPool does NOT auto-reconnect dead connections; if all idle connections die (DB restart), next `acquire()` hangs until its default timeout
- Research recommends 3 layers: retry on connect (3 attempts, 2s base backoff, 30s cap), acquire_timeout on pool, background health probe (30s interval)
- Circuit breaker for DB queries is YAGNI for now — retry + health check sufficient

## Requirements

**Functional:**
- `retry_connect()`: 3 attempts with exponential backoff (2s, 4s), 30s cap
- `acquire_timeout`: 5s on `PgPoolOptions` (fail fast when pool exhausted)
- `health_check_loop()`: background task probes pool every 30s, warns on failure
- New `StorageError::ConnectionFailed(String)` variant for exhausted retries

**Non-functional:**
- Startup latency: +2-6s worst case (3 attempts x 2s backoff)
- Health check overhead: 1 query per 30s (negligible)
- No behavior change when DB is healthy (immediate connect, no extra latency)

## Architecture

**Data flow (startup):**
```
Database::connect()
  → retry_connect(url, max_conns)
    → attempt 1: PgPoolOptions.connect() → Ok? return pool
    → attempt 2: sleep(2s), retry → Ok? return pool
    → attempt 3: sleep(4s), retry → Ok? return pool
    → all failed: StorageError::ConnectionFailed
  → spawn health_check_loop(pool.clone())
  → Ok(Self { pool, event_tx })
```

**Data flow (runtime health):**
```
health_check_loop (every 30s):
  → timeout(5s, pool.acquire())
    → Ok: connection healthy, returned to pool
    → Err: warn! "pool health check: acquire failed"
    → Timeout: warn! "pool health check: timeout"
```

## Related Code Files

| File | Action | LOC Est. | Test Impact |
|------|--------|----------|-------------|
| `crates/waf-storage/src/db.rs` | Modify | ~60 added | 3 new tests |
| `crates/waf-storage/src/error.rs` | Modify | +3 lines | — |

## Tests Before (TDD)

1. **Test: connect fails on invalid URL (baseline)**
   - `Database::connect("postgres://invalid:5432/x", 5)` → Err
   - Documents current single-attempt behavior

2. **Test: StorageError::ConnectionFailed variant exists**
   - Write test asserting the new variant can be constructed and displays correctly
   - This test will fail until error.rs is updated

3. **Test: acquire_timeout causes fast failure**
   - Create pool with `acquire_timeout(1s)` and `max_connections(1)`
   - Hold the single connection, try to acquire second
   - Assert: fails within ~1s, not hanging indefinitely

## Implementation Steps

1. **Add error variant** to `crates/waf-storage/src/error.rs`:
   ```rust
   #[error("Connection failed: {0}")]
   ConnectionFailed(String),
   ```

2. **Add constants** to `db.rs`:
   ```rust
   const CONNECT_RETRY_ATTEMPTS: u32 = 3;
   const CONNECT_RETRY_BASE: Duration = Duration::from_secs(2);
   const CONNECT_RETRY_CAP: Duration = Duration::from_secs(30);
   const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);
   const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
   const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);
   ```

3. **Extract `retry_connect()`** from `Database::connect()`:
   ```rust
   async fn retry_connect(
       database_url: &str,
       max_connections: u32,
   ) -> Result<PgPool, StorageError> {
       let mut backoff = CONNECT_RETRY_BASE;
       for attempt in 1..=CONNECT_RETRY_ATTEMPTS {
           info!(attempt, "PostgreSQL connect attempt {}/{}", attempt, CONNECT_RETRY_ATTEMPTS);
           match PgPoolOptions::new()
               .max_connections(max_connections)
               .acquire_timeout(ACQUIRE_TIMEOUT)
               .connect(database_url)
               .await
           {
               Ok(pool) => {
                   info!("PostgreSQL connection established");
                   return Ok(pool);
               }
               Err(e) if attempt < CONNECT_RETRY_ATTEMPTS => {
                   warn!(error = %e, backoff_secs = backoff.as_secs(),
                       "Connect failed; retrying in {:?}", backoff);
                   tokio::time::sleep(backoff).await;
                   backoff = (backoff * 2).min(CONNECT_RETRY_CAP);
               }
               Err(e) => {
                   return Err(StorageError::ConnectionFailed(
                       format!("Failed after {} attempts: {}", CONNECT_RETRY_ATTEMPTS, e),
                   ));
               }
           }
       }
       // RED-TEAM FIX: removed unreachable!() — Iron Rules ban panic-capable macros.
       // The for loop exhausts all attempts; final Err arm always returns.
       // This line is provably unreachable, but use error return as safety net:
       Err(StorageError::ConnectionFailed("retry loop exited unexpectedly".into()))
   }
   ```

4. **Add `health_check_loop()`**:
   ```rust
   async fn health_check_loop(pool: PgPool) {
       let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
       loop {
           interval.tick().await;
           // RED-TEAM FIX: use SELECT 1 instead of pool.acquire() — returns connection
           // immediately rather than holding it for up to 5s under contention
           match tokio::time::timeout(
               HEALTH_CHECK_TIMEOUT,
               sqlx::query("SELECT 1").execute(&pool),
           ).await {
               Ok(Ok(_)) => { /* healthy */ }
               Ok(Err(e)) => warn!(error = %e, "Pool health check: query failed"),
               Err(_) => warn!("Pool health check: timeout after {:?}", HEALTH_CHECK_TIMEOUT),
           }
       }
   }
   ```

5. **Update `Database::connect()`** (db.rs:18-29):
   ```rust
   pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
       info!("Connecting to PostgreSQL: {}", sanitize_url(database_url));
       let pool = retry_connect(database_url, max_connections).await?;
       let (event_tx, _) = broadcast::channel(1024);
       // Background health monitor
       let health_pool = pool.clone();
       tokio::spawn(async move { health_check_loop(health_pool).await });
       Ok(Self { pool, event_tx })
   }
   ```

6. **Add imports**: `use std::time::Duration; use tracing::{info, warn};`

## Refactor

Changes to `db.rs` (~60 lines added):
- `connect()`: replace direct `PgPoolOptions.connect()` with `retry_connect()` + spawn health check
- New `retry_connect()` function (~25 lines)
- New `health_check_loop()` function (~15 lines)
- Constants block (~6 lines)

Changes to `error.rs` (+3 lines):
- Add `ConnectionFailed(String)` variant

## Tests After (TDD)

1. **Test: retry_connect retries on failure**
   - Use invalid URL; assert error message contains "after 3 attempts"
   - Verify it took >2s (proves backoff happened)

2. **Test: health_check_loop logs warn on unreachable pool**
   - Start health check with closed pool
   - Assert: warn log emitted within one interval

3. **Test: successful connect with acquire_timeout set**
   - Connect to real test DB (if available) or mock
   - Assert: pool has acquire_timeout configured

## Regression Gate

```bash
cargo check -p waf-storage
cargo test -p waf-storage
```

## Success Criteria

- [ ] `retry_connect()` with 3 attempts + exponential backoff
- [ ] `acquire_timeout(5s)` on PgPoolOptions
- [ ] `health_check_loop()` spawned as background task
- [ ] `StorageError::ConnectionFailed` variant added
- [ ] All existing tests pass
- [ ] 3+ new tests passing
- [ ] `cargo check -p waf-storage` clean

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Startup latency increase (cold start) | Certain | Low | +2-6s only on failure; instant when DB reachable |
| Health check masks real connection issues | Low | Low | Health check only warns, doesn't auto-fix; operators react to logs |
| New error variant breaks match arms | Low | Low | **RED-TEAM**: grep for exhaustive matches on `StorageError` before adding variant. If found, update them. Only one caller (main.rs) uses `?` propagation — low risk. |

## Test Scenario Matrix

| Scenario | Priority | Type |
|----------|----------|------|
| Connect succeeds first attempt | Critical | Unit |
| Connect fails all attempts → ConnectionFailed | Critical | Unit |
| Connect fails then succeeds on retry 2 | High | Unit |
| acquire_timeout prevents indefinite hang | High | Unit |
| Health check warns on failure | Medium | Integration |
| Health check silent on success | Medium | Integration |

## Dependency Map

- **Depends on**: nothing
- **Blocks**: Phase 7 (integration)
- **File ownership**: `crates/waf-storage/src/db.rs`, `crates/waf-storage/src/error.rs` — exclusive to this phase
