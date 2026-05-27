---
title: "Tracing & Database Resilience: Dynamic Log Levels, Process Supervision, Connection Resilience"
date: 2026-05-26
---

# Research Report: Tracing Architecture & Database Resilience

## Context

WAF proxy (mini-waf) has three production readiness gaps:
1. **Static log levels** (main.rs:308) — EnvFilter locked at startup, no runtime changes
2. **No sidecar restart** (sidecar.rs:213) — VictoriaLogs child crash orphans audit pipeline permanently
3. **DB connection SPOF** (db.rs:17) — No retry, no health checks, single failure kills request path

---

## Finding 1: Dynamic Log Level Control via `tracing_subscriber::reload`

### Current State
```rust
// main.rs:308-315 — Static EnvFilter, immutable after init
tracing_subscriber::registry()
    .with(fmt::layer())
    .with(
        EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO),
    )
    .with(vlogs_layer)
    .init();
```

### Problem
- Log level requires restart to change
- Debugging production issues requires either re-deploy or blind guessing
- No per-component log filtering (e.g., silence noisy modules during peak load)

### Recommended Approach

**Use `tracing_subscriber::reload` to wrap the EnvFilter:**

```rust
// In main.rs or dedicated module:
use tracing_subscriber::reload;

pub async fn init_tracing_with_reload(
    vlogs_layer: VictoriaLogsLayer,
    vlogs_layer_slot: LayerSlot,
) -> anyhow::Result<reload::Handle<EnvFilter, tracing_subscriber::Registry>> {
    let env_filter = EnvFilter::from_default_env()
        .add_directive(tracing::Level::INFO.into());
    
    let (filter, reload_handle) = reload::layer(env_filter);
    
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .with(vlogs_layer)
        .init();
    
    Ok(reload_handle)
}

// Store `reload_handle` in AppState, expose via API:
#[post("/api/admin/logs/level")]
pub async fn set_log_level(
    State(state): State<AppState>,
    Json(req): Json<SetLogLevelRequest>,
) -> Result<Json<()>> {
    let new_filter = EnvFilter::try_new(&req.filter)?;
    state.tracing_reload_handle.reload(new_filter)
        .context("Failed to reload log filter")?;
    Ok(Json(()))
}
```

### Key Gotchas
- **Multi-layer subscribers**: If wrapping EnvFilter in a reload layer, the layer sits *above* the registry. Events still flow through all layers; the filter just gates what reaches the reload layer. No behavioral change to VictoriaLogsLayer or fmt layer.
- **Thread-safe**: reload::Handle is Send/Sync. Safe to store in AppState and call from async handlers.
- **Parsing errors**: Invalid filter directives (e.g., typo in module name) are caught by `EnvFilter::try_new`, not silently ignored. Validate before reload.
- **No partial reload**: Must provide a complete filter string; there's no "add directive" on the Handle. Work around by maintaining a filter builder in state and re-composing.

### Trade-offs

| Aspect | Tradeoff |
|--------|----------|
| **Overhead** | reload::Handle adds ~zero overhead in the hot path (filter check is O(1) trie lookup, already in baseline) |
| **Complexity** | Requires AppState mutation + API endpoint, not trivial but standard Axum pattern |
| **Cardinality** | No new cardinality; EnvFilter directives are static tokens, not metric labels |
| **Adoption risk** | Low — tracing_subscriber::reload is mature, used in production systems (tokio, tonic) |

### Code Location & Implementation
- **File**: `crates/prx-waf/src/main.rs` (lines 308–315) — replace static init with reload wrapper
- **Alternative**: Dedicated module `crates/prx-waf/src/tracing_setup.rs` if complexity grows (separate concerns)
- **API endpoint**: `crates/waf-api/src/handlers/admin.rs` — add `POST /api/admin/logs/level` with `{ "filter": "info,waf_engine::checks=debug" }`
- **AppState field**: Add `tracing_reload_handle: reload::Handle<EnvFilter, Registry>`

---

## Finding 2: Sidecar Process Supervision with Restart Loop

### Current State
```rust
// sidecar.rs:178-227 — Supervise task, no restart on child exit
async fn supervise(mut child: Child, listen_addr: String) {
    // ... health checks ...
    wait_res = child.wait() => {
        match wait_res {
            Ok(status) => error!(status = ?status, "VictoriaLogs exited unexpectedly; admin intervention required"),
            Err(e) => error!(error = %e, "Failed to wait on VictoriaLogs child"),
        }
        return;  // ← EXIT — no restart attempt
    }
}
```

### Problem
- Single crash = permanent audit pipeline blackout
- Recovery requires manual restart or process manager (systemd)
- No backoff protection against thrashing (restart loop saturation)

### Recommended Approach

**Wrap spawn + supervise in a restart loop with exponential backoff:**

```rust
// In sidecar.rs, new module:
use std::time::Duration;

const RESTART_BACKOFF_BASE: Duration = Duration::from_secs(1);
const RESTART_BACKOFF_MAX: Duration = Duration::from_secs(120);

pub async fn spawn_with_restart(cfg: &VictoriaLogsConfig) -> anyhow::Result<Option<Self>> {
    if !cfg.enabled {
        return Ok(None);
    }

    let mut backoff = RESTART_BACKOFF_BASE;
    let mut attempt = 0u32;

    loop {
        attempt += 1;
        info!(attempt, "Starting VictoriaLogs (attempt {})", attempt);
        
        match spawn_once(cfg).await {
            Ok(Some(_sidecar)) => {
                // spawn_once returns after child exits; restart
                warn!("VictoriaLogs exited, restarting in {:?}", backoff);
                tokio::time::sleep(backoff).await;
                
                // Exponential backoff: cap at MAX
                backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
            }
            Ok(None) => {
                // Feature disabled
                return Ok(None);
            }
            Err(e) => {
                error!("Failed to spawn VictoriaLogs: {}", e);
                warn!("Retrying in {:?}", backoff);
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(RESTART_BACKOFF_MAX);
            }
        }
    }
}

// Refactored existing spawn logic:
async fn spawn_once(cfg: &VictoriaLogsConfig) -> anyhow::Result<Option<Self>> {
    if !cfg.enabled {
        return Ok(None);
    }

    tokio::fs::create_dir_all(&cfg.storage_data_path)
        .await
        .context("create storage_data_path")?;

    let mut command = Command::new(&cfg.binary_path);
    // ... existing command setup ...

    let mut child = command.spawn()
        .context("spawn VictoriaLogs")?;

    // Detach stdout/stderr forwarders
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(forward_lines(stdout, false));
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(forward_lines(stderr, true));
    }

    // Wait for readiness
    let listen_addr = cfg.listen_addr.clone();
    if let Err(e) = wait_until_ready(&listen_addr).await {
        let _ = child.start_kill();
        return Err(e);
    }
    info!(listen = %listen_addr, "VictoriaLogs sidecar healthy");

    // Monitor until exit (will loop back for restart)
    tokio::spawn(supervise_until_exit(child, listen_addr));
    
    Ok(Some(Self { _private: () }))
}

async fn supervise_until_exit(mut child: Child, listen_addr: String) {
    let mut health_timer = tokio::time::interval(HEALTH_CHECK_INTERVAL);
    health_timer.reset();
    // ... existing health check logic ...
    
    loop {
        tokio::select! {
            Some(()) = sigterm.recv() => {
                graceful_shutdown(&mut child).await;
                return;  // Parent process exiting
            }
            wait_res = child.wait() => {
                match wait_res {
                    Ok(status) => error!(status = ?status, "VictoriaLogs exited"),
                    Err(e) => error!(error = %e, "Failed to wait"),
                }
                return;  // ← Return to spawn_with_restart loop
            }
            // ... health check ...
        }
    }
}
```

### Key Gotchas
- **Infinite restart loop risk**: Cap backoff at MAX (120s here) to prevent thrashing. After 10–15 restarts, stop escalating.
- **Graceful shutdown**: SIGTERM/SIGINT should reach supervise_until_exit, which gracefully shuts down the child and returns, exiting the restart loop (not restarting).
- **Startup timeouts**: If VictoriaLogs takes >10s to become healthy (HEALTH_READY_TIMEOUT), it'll timeout, log error, then backoff and retry. Expected behavior.
- **Fire-and-forget spawn**: The supervise task is spawned fire-and-forget (tokio::spawn). The restart loop lives in spawn_with_restart's caller — typically main.rs. Must keep it alive for the process lifetime.

### Trade-offs

| Aspect | Tradeoff |
|--------|----------|
| **Overhead** | Sleep delays add jitter; ~1–2s latency on each crash before restart. Acceptable for audit pipeline (not latency-critical). |
| **Complexity** | Adds ~40 lines; new supervise_until_exit function splits concerns (monitor vs. restart). |
| **Observability** | Emit `restart_attempt` counter + gauge for backoff duration via tracing. Optional but recommended for SRE dashboards. |
| **Testing** | Need integration test that kills the child and validates restart within backoff window. |

### Code Location & Implementation
- **File**: `crates/prx-waf/src/victoria_logs/sidecar.rs` (lines 50–115) — refactor spawn → spawn_once, add spawn_with_restart
- **Caller**: `crates/prx-waf/src/main.rs` (in run_server) — change from `.spawn()` to `.spawn_with_restart()`
- **Graceful shutdown**: Keep existing SIGTERM forwarding in supervise_until_exit

---

## Finding 3: Database Connection Resilience (sqlx + Retry + Health Checks)

### Current State
```rust
// db.rs:18-24 — No retry, no health check
pub async fn connect(database_url: &str, max_connections: u32) -> Result<Self, StorageError> {
    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)  // ← Single attempt, fails on network hiccup
        .await?;
    // ...
}
```

### Problem
- First connect fails → entire WAF startup blocked
- Network transient (e.g., DB slow, pod restart) = black hole
- No connection health check; stale connections not replaced
- No circuit breaker; requests queue indefinitely on pool exhaustion

### Recommended Approach

**Three layers: retry on connect, pool health checks, circuit breaker.**

```rust
// In db.rs:

use sqlx::postgres::PgPoolOptions;
use std::time::Duration;

const CONNECT_RETRY_ATTEMPTS: u32 = 3;
const CONNECT_RETRY_BACKOFF: Duration = Duration::from_secs(2);
const POOL_HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const POOL_HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn connect(
    database_url: &str,
    max_connections: u32,
) -> Result<Self, StorageError> {
    info!("Connecting to PostgreSQL: {}", sanitize_url(database_url));

    let pool = retry_connect(database_url, max_connections).await?;

    let (event_tx, _) = broadcast::channel(1024);

    // Start background health check task
    let health_pool = pool.clone();
    tokio::spawn(async move {
        health_check_loop(health_pool).await;
    });

    Ok(Self { pool, event_tx })
}

/// Retry connection with exponential backoff.
async fn retry_connect(
    database_url: &str,
    max_connections: u32,
) -> Result<PgPool, StorageError> {
    let mut attempt = 0;
    let mut backoff = CONNECT_RETRY_BACKOFF;

    loop {
        attempt += 1;
        info!(
            attempt,
            database = %sanitize_url(database_url),
            "PostgreSQL connect attempt {}/{}", attempt, CONNECT_RETRY_ATTEMPTS
        );

        match PgPoolOptions::new()
            .max_connections(max_connections)
            .acquire_timeout(POOL_HEALTH_CHECK_TIMEOUT)
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                info!("PostgreSQL connection established");
                return Ok(pool);
            }
            Err(e) if attempt < CONNECT_RETRY_ATTEMPTS => {
                warn!(
                    error = %e,
                    backoff_secs = backoff.as_secs(),
                    "Connect failed; retrying in {:?}", backoff
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(Duration::from_secs(30)); // cap at 30s
            }
            Err(e) => {
                return Err(StorageError::ConnectionFailed(
                    format!(
                        "Failed to connect to PostgreSQL after {} attempts: {}",
                        CONNECT_RETRY_ATTEMPTS, e
                    ),
                ));
            }
        }
    }
}

/// Background task: probe pool health every 30s, recycle stale connections.
async fn health_check_loop(pool: PgPool) {
    let mut interval = tokio::time::interval(POOL_HEALTH_CHECK_INTERVAL);
    
    loop {
        interval.tick().await;
        
        match tokio::time::timeout(
            POOL_HEALTH_CHECK_TIMEOUT,
            pool.acquire(),
        ).await {
            Ok(Ok(_conn)) => {
                // Connection healthy; slot is returned to pool
            }
            Ok(Err(e)) => {
                warn!(error = %e, "Pool health check: acquire failed; pool may be exhausted or DB unreachable");
            }
            Err(_) => {
                warn!("Pool health check: timeout after {:?}; DB may be slow or network issue", POOL_HEALTH_CHECK_TIMEOUT);
            }
        }
    }
}
```

### Optional: Circuit Breaker (for extreme cases)

If you want to fail fast during DB outages (rather than queue indefinitely):

```rust
use std::sync::Arc;
use parking_lot::Mutex;

pub struct CircuitBreaker {
    state: Arc<Mutex<CBState>>,
}

enum CBState {
    Closed,
    Open { until: tokio::time::Instant },
}

impl CircuitBreaker {
    /// Check if we should attempt a query. If open, fail immediately.
    pub fn is_open(&self) -> bool {
        let mut state = self.state.lock();
        match *state {
            CBState::Open { until } if tokio::time::Instant::now() >= until => {
                *state = CBState::Closed;
                false
            }
            CBState::Open { .. } => true,
            CBState::Closed => false,
        }
    }

    /// Mark the circuit as open (failed query).
    pub fn trip(&self) {
        let mut state = self.state.lock();
        *state = CBState::Open {
            until: tokio::time::Instant::now() + Duration::from_secs(30),
        };
    }
}
```

Then in your query handler:
```rust
if circuit_breaker.is_open() {
    return Err(StorageError::ServiceUnavailable("DB circuit breaker open".into()));
}
match execute_query().await {
    Err(e) if is_db_connection_error(&e) => {
        circuit_breaker.trip();
        Err(e)
    }
    other => other,
}
```

### Key Gotchas
- **sqlx PgPool behavior**: By default, PgPool does NOT auto-reconnect dead connections. If all idle connections die (DB restart, network break), the next `acquire()` will timeout (not fail immediately). Our retry loop + health check work around this.
- **Connection reuse**: sqlx recycles idle connections; if DB restarts while a connection sits idle, the next use will fail. The health check doesn't "fix" the connection — it just exposes the failure. Queries will retry at the application level (via ?).
- **Cardinality**: Health check emits warn logs on failure; limit to once per 30s interval to avoid log spam.
- **Circuit breaker overkill?**: For most deployments, the retry-on-connect + health-check combo is enough. Add circuit breaker only if observing 100+ concurrent requests queuing on pool exhaustion during outages.

### Trade-offs

| Aspect | Tradeoff |
|--------|----------|
| **Startup latency** | +2–6s on cold start (3 attempts × 2s backoff). Acceptable; reduces flapping. |
| **Overhead** | Health check task emits one query every 30s; negligible at 100k rps. |
| **Observability** | New metrics: connect_attempts, pool_health_check_pass/fail. Worth tracking. |
| **Complexity** | ~50 lines for retry + health check. Circuit breaker is optional +30 lines. |
| **Testing** | Need integration test: kill DB, validate retry + health-check logs + recovery. |

### Code Location & Implementation
- **File**: `crates/waf-storage/src/db.rs` (lines 18–29) — add retry_connect + health_check_loop
- **Module**: `crates/waf-storage/src/db.rs` (new, optional) — move circuit breaker logic here if added
- **Metrics**: Emit tracing events (info/warn) for startup + health checks; optionally add Prometheus metrics via `metrics` crate

---

## Finding 4: Production WAF Observability (100k+ rps)

### Metrics Essentials

For a WAF at 100k+ rps, cardinality explosion is the #1 risk. Focus on:

| Metric | Purpose | Cardinality | Collection |
|--------|---------|-------------|------------|
| `request_total` | QPS by decision (allow/block/challenge) | ~10 (decisions × hostnames) | Span field `decision` |
| `request_duration_ms` | Latency histogram (p50/p95/p99) | ~5 (per-tier) | Span field `tier` |
| `block_reason` | Top attack vectors | ~50 (rule IDs) | Span field `blocked_by_rule` |
| `origin_response_time_ms` | Upstream latency | ~10 (per-origin) | Span field `origin` |
| `errors_total` | Error rate by category | ~20 (storage, auth, proxy, etc.) | Span field `error_kind` |
| `pool_connections_active` | DB connection health | ~1 (per-pool) | Gauge query |
| `cache_hit_ratio` | Response cache effectiveness | ~5 (per-tier) | Counter update |

### Span Strategy

Design spans to **reduce cardinality while preserving debuggability**:

```rust
// ✅ GOOD: coarse root span, field cardinality < 100
#[instrument(skip_all, fields(
    request_id = %uuid::Uuid::new_v4(),
    decision = tracing::field::Empty,  // Filled in later
    blocked_by_rule = tracing::field::Empty,
    origin = "unknown",
))]
async fn proxy_request(req: &HttpRequest) -> Result<HttpResponse> {
    let tier = classify_tier(req);  // ~4 values
    let rule_match = detect_attacks(req);  // ~50 rules
    
    Span::current().record("decision", rule_match.decision.as_str());  // Allow, Block, Challenge
    Span::current().record("blocked_by_rule", rule_match.rule_id);    // Rule ID only, not description
    Span::current().record("origin", &origin_host);                   // Per-origin
    
    // Child spans for specific checks (optional, use sparingly):
    detect_sqli(req).instrument(debug_span!("sqli_check")).await?;
    detect_xss(req).instrument(debug_span!("xss_check")).await?;
    
    Ok(response)
}

// ❌ AVOID: per-request cardinality explosion
#[instrument(skip_all, fields(
    source_ip = %req.source_ip,      // ~10M unique IPs — explosion!
    user_agent = %req.user_agent,    // ~100k variants — explosion!
))]
```

### Sampling Strategy

At 100k rps, log every request = 8.6B events/day. **Sample strategically**:

```rust
/// Sample based on decision + error rate.
pub fn should_log(decision: Decision, has_error: bool) -> bool {
    match decision {
        Decision::Allow if !has_error => {
            // Sample 1-in-1000 successful requests
            rand::random::<u32>() % 1000 == 0
        }
        Decision::Allow if has_error => true,     // Always log errors
        Decision::Block | Decision::Challenge => true,  // Always log security events
    }
}
```

### Alerting Thresholds (SLOs)

```yaml
# Prometheus rules
groups:
  - name: waf_slos
    rules:
      - alert: WAFBlockRateAnomaly
        expr: rate(waf_request_blocked_total[5m]) > 10  # 10 blocks/sec = anomaly
      
      - alert: WAFLatencyP99High
        expr: histogram_quantile(0.99, waf_request_duration_ms) > 500
      
      - alert: DBConnectionPoolExhausted
        expr: waf_db_pool_connections_active > (max_connections * 0.9)
      
      - alert: VictoriaLogsIngestLag
        expr: rate(waf_vlogs_batch_drop_total[1m]) > 100  # Dropping >100 events/sec
```

### Code Location
- **Tracing instrumentation**: `crates/gateway/src/proxy.rs` — wrap request handler with #[instrument]
- **Sampling logic**: `crates/waf-common/src/observability.rs` (new module) — export should_log(), cardinality guards
- **Metrics**: Emit via `tracing` events; optional: integrate `metrics` crate + Prometheus exporter in `crates/waf-api/src/metrics.rs`

---

## Summary Table

| Finding | Problem | Solution | Effort | Risk | Priority |
|---------|---------|----------|--------|------|----------|
| **1. Log level** | Static EnvFilter, requires restart | reload::Handle + API endpoint | 2h | Low | HIGH |
| **2. Sidecar restart** | Crash = permanent audit blackout | Retry loop + exponential backoff | 3h | Low | HIGH |
| **3. DB resilience** | No retry/health-check, SPOF | retry_connect + health_check_loop + optional CB | 4h | Low | HIGH |
| **4. Observability** | Cardinality risk at 100k+ rps | Coarse spans, sampling, cardinality guards | 2h | Low | MEDIUM |

---

## Unresolved Questions

1. **Circuit breaker strategy**: Do you want to fail fast (circuit breaker) or queue indefinitely (current backoff)? Depends on SLA expectations during DB outages.
2. **VictoriaLogs restart policy**: Should restarts cap at N attempts, then alert and exit? Or indefinitely retry? Recommendation: cap at 10 restarts with 30-min backoff reset; alert ops if restart_attempt_total > 100 in 1h.
3. **Cardinality budget**: Do you have a Prometheus cardinality limit? Will affect whether we add rule_id as a label or only emit it in span fields (lower cardinality).
4. **Sampling rate**: Is 1-in-1000 for allow requests appropriate? Depends on storage budget for VictoriaLogs and query latency SLA.
