---
phase: 4
title: "Smart Tracing and Log Sampling"
findings: [F8, F10]
status: pending
priority: P2
effort: "3h"
dependencies: []
---

# Phase 4: Smart Tracing and Log Sampling

## Overview

Two combined findings: (F10) static `EnvFilter` at `main.rs:308-315` requires restart to change log levels; (F8) per-request `info!()` at `proxy.rs:488` floods logs at scale. Fix: (a) dynamic log level via `tracing_subscriber::reload`, (b) demote per-request log to `debug!()`, (c) expose admin API endpoint for runtime level changes.

## Key Insights

- Current init at main.rs:308-315: `tracing_subscriber::registry().with(fmt::layer()).with(EnvFilter::from_default_env()...).init()` — immutable after startup
- `tracing_subscriber::reload` is mature (used in tokio, tonic), adds ~zero overhead in hot path
- `proxy.rs:488`: `info!("Proxying {} → {}", host_header, upstream_addr)` — 1 log per request, noise at 10k rps
- `AppState` (waf-api/src/state.rs) is the natural place to store the reload handle
- Admin routes in `waf-api/src/server.rs:87` — add new endpoint to protected routes
- Sampling filter (1-in-N for VictoriaLogs layer) is optional polish; start with level demotion

## Requirements

**Functional:**
- Replace static `EnvFilter` with `reload::Layer` wrapper
- Store `reload::Handle` in `AppState`
- Add `POST /api/admin/logs/level` with body `{ "filter": "info,waf_engine=debug" }`
- Validate filter string before applying (reject invalid with 400)
- Demote `proxy.rs:488` from `info!()` to `debug!()`

**Non-functional:**
- Zero overhead in hot path (reload layer checks are O(1) trie lookup)
- Admin endpoint auth-protected (existing middleware)
- Invalid filter → 400 error, no state change

## Architecture

**Data flow (startup):**
```
main.rs → EnvFilter → reload::layer(filter)
  → (reload::Layer, reload::Handle)
  → registry.with(reload_layer).with(fmt).with(vlogs).init()
  → handle stored in AppState
```

**Data flow (runtime change):**
```
POST /api/admin/logs/level { "filter": "debug,waf_engine::rules=trace" }
  → handler validates with EnvFilter::try_new()
  → state.tracing_reload_handle.reload(new_filter)
  → immediate effect on all log output
```

## Related Code Files

| File | Action | LOC Est. | Test Impact |
|------|--------|----------|-------------|
| `crates/prx-waf/src/main.rs` | Modify | ~15 changed (lines 308-315) | — |
| `crates/gateway/src/proxy.rs` | Modify | 1 line (line 488) | — |
| `crates/waf-api/src/state.rs` | Modify | +3 lines (new field) | — |
| `crates/waf-api/src/server.rs` | Modify | +1 route | — |
| `crates/waf-api/src/handlers.rs` | Modify | +25 (handler fn) | 2 new tests |

## Tests Before (TDD)

1. **Test: EnvFilter::try_new rejects invalid filter string**
   - `EnvFilter::try_new("not a valid [filter")` → Err
   - Documents validation contract for handler

2. **Test: reload::Handle can swap filter**
   - Create subscriber with reload layer
   - Reload with new filter
   - Assert: no error, handle reports success

3. **Test: proxy.rs info log is now debug**
   - After demotion: with default `info` level, the per-request log should NOT appear
   - Verify by checking tracing test subscriber output at info level

## Implementation Steps

### Part A: Dynamic Log Level (F10)

1. **Modify `main.rs:308-315`** — wrap EnvFilter in reload:

   ```rust
   // BEFORE (main.rs:308-315):
   tracing_subscriber::registry()
       .with(fmt::layer())
       .with(EnvFilter::from_default_env()
           .add_directive(tracing::Level::INFO.into()))
       .with(vlogs_layer)
       .init();

   // AFTER:
   use tracing_subscriber::reload;

   let env_filter = EnvFilter::from_default_env()
       .add_directive(tracing::Level::INFO.into());
   let (filter_layer, reload_handle) = reload::layer(env_filter);

   // RED-TEAM FIX: filter_layer MUST be outermost (applied to registry first)
   // to filter ALL downstream layers (fmt + vlogs). tracing-subscriber processes
   // layers bottom-up: registry → filter → fmt → vlogs. Placing filter_layer
   // BEFORE fmt/vlogs means it gates events entering the entire stack.
   tracing_subscriber::registry()
       .with(filter_layer)  // global filter — gates both fmt and vlogs
       .with(fmt::layer())
       .with(vlogs_layer)
       .init();
   // Pass reload_handle to AppState
   ```

2. **Add field to `AppState`** (state.rs:13):
   - **RED-TEAM**: `AppState::new()` already has many `Option` fields set to `None` then mutated before `Arc::new(state)` — follow same pattern
   - Use closure wrapper to erase complex `reload::Handle` generics:
   
   ```rust
   // In state.rs:
   pub log_level_setter: Option<Arc<dyn Fn(&str) -> anyhow::Result<()> + Send + Sync>>,
   ```
   - Initialize as `None` in `new()`, set before wrapping in `Arc`

3. **Wire in main.rs** — after creating reload_handle, BEFORE `Arc::new(state)`:
   ```rust
   let handle = reload_handle.clone();
   let setter: Arc<dyn Fn(&str) -> anyhow::Result<()> + Send + Sync> = Arc::new(move |filter_str| {
       let new_filter = EnvFilter::try_new(filter_str)
           .context("invalid filter directive")?;
       handle.reload(new_filter).context("failed to reload filter")?;
       Ok(())
   });
   api_state.log_level_setter = Some(setter);
   // Then: let state = Arc::new(api_state);
   ```

4. **Add handler** in `handlers.rs` or new `log_level.rs`:
   ```rust
   #[derive(Deserialize)]
   pub struct SetLogLevelRequest { pub filter: String }

   pub async fn set_log_level(
       State(state): State<Arc<AppState>>,
       Json(req): Json<SetLogLevelRequest>,
   ) -> Result<Json<serde_json::Value>, ApiError> {
       let setter = state.log_level_setter.as_ref()
           .ok_or_else(|| ApiError::internal("log level control not initialized"))?;
       setter(&req.filter).map_err(|e| ApiError::bad_request(e.to_string()))?;
       info!("Log filter updated to: {}", req.filter);
       Ok(Json(json!({"status": "ok", "filter": req.filter})))
   }
   ```

5. **Register route** in `server.rs:87` (protected_routes):
   ```rust
   .route("/api/admin/logs/level", post(set_log_level))
   ```

### Part B: Log Demotion (F8)

6. **Demote proxy.rs:488** — single line change:
   ```rust
   // BEFORE:
   info!("Proxying {} → {}", host_header, upstream_addr);
   // AFTER:
   debug!("Proxying {} → {}", host_header, upstream_addr);
   ```

## Refactor

Summary of changes:
- `main.rs:308-315`: add `reload::layer()` wrapper (~10 lines)
- `state.rs`: add `log_level_setter` field (+3 lines)
- `handlers.rs`: add `set_log_level` handler (~25 lines)
- `server.rs`: add 1 route
- `proxy.rs:488`: `info!` → `debug!` (1 line)

## Tests After (TDD)

1. **Test: POST /api/admin/logs/level with valid filter → 200**
   - Body: `{"filter": "info,waf_engine=debug"}`
   - Assert: 200 OK

2. **Test: POST /api/admin/logs/level with invalid filter → 400**
   - Body: `{"filter": "[broken"}`
   - Assert: 400 Bad Request

## Regression Gate

```bash
cargo check -p prx-waf -p waf-api -p gateway
cargo test -p waf-api
cargo test -p gateway
```

## Success Criteria

- [ ] `reload::Handle` replaces static `EnvFilter`
- [ ] `POST /api/admin/logs/level` endpoint works (auth-protected)
- [ ] Invalid filter rejected with 400
- [ ] `proxy.rs:488` demoted to `debug!()`
- [ ] All existing tests pass
- [ ] `cargo check --workspace` clean

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Complex reload::Handle type breaks compilation | Medium | Low | Use closure wrapper to erase type |
| Log level change persists across restarts unexpectedly | None | — | Reload is in-memory only; restart restores env default |
| Demoting proxy log loses ops visibility | Low | Low | Operators enable debug via new endpoint when needed |
| Multi-layer subscriber interaction | Low | Medium | Test with both fmt + vlogs layers active |
| Admin sets `filter: "trace"` → log volume DoS | Low | Medium | **RED-TEAM**: add max-length check (256 chars) on filter string. Log old+new filter values for audit trail. Rate limit to 1 change/10s. |

## Test Scenario Matrix

| Scenario | Priority | Type |
|----------|----------|------|
| Valid filter reload → success | Critical | Integration |
| Invalid filter → 400 rejection | Critical | Unit |
| info! → debug! demotion verified | High | Unit |
| Auth required for endpoint | High | Integration |
| Filter survives high-concurrency requests | Medium | Stress |

## Dependency Map

- **Depends on**: nothing
- **Blocks**: Phase 7 (integration)
- **File ownership**: `main.rs`, `proxy.rs`, `state.rs`, `server.rs`, `handlers.rs` — exclusive to this phase
