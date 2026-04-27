# Phase 03 — Hot Reload

## Priority
P0 — shipped with the feature, depends on Phase 02.

## Objective
Operators can change masking denylists / regex / enabled flag without restarting the WAF. Reload is **atomic** (no torn reads) and **lock-free on the hot path**.

## Mechanisms (two triggers, one swap)
1. **Admin API**: `POST /api/log-masking/reload` — re-reads config file from disk, rebuilds `Masker`, `ArcSwap::store()`s it.
2. **Optional file watcher**: when `log_masking.watch_config_file = true`, spawn `notify::RecommendedWatcher` on the config file path; debounce 500 ms; on change, run the same rebuild path as the API.

Both call a single function: `Engine::reload_log_masking(config_path: &Path) -> anyhow::Result<()>`.

## Files to Modify
- `crates/waf-engine/src/engine.rs` — add `pub async fn reload_log_masking(&self, cfg_path: &Path) -> anyhow::Result<()>`
- `crates/waf-api/src/handlers.rs` — add `reload_log_masking` handler
- `crates/waf-api/src/server.rs` — route `POST /api/log-masking/reload`
- `crates/waf-engine/src/log_masking_watcher.rs` **(new, optional)** — file-watcher loop; skip creation if scope pressure rises
- `crates/prx-waf/src/main.rs` — if `watch_config_file`, spawn watcher task after engine boot

## Handler Sketch
```rust
pub async fn reload_log_masking(
    State(state): State<Arc<AppState>>,
) -> ApiResult<Json<Value>> {
    state
        .engine
        .reload_log_masking(&state.config_path)
        .await
        .map_err(ApiError::Internal)?;
    Ok(Json(json!({ "success": true, "data": "Log masking reloaded" })))
}
```

## Engine Method Sketch
```rust
pub async fn reload_log_masking(&self, cfg_path: &Path) -> anyhow::Result<()> {
    let raw = tokio::fs::read_to_string(cfg_path).await
        .with_context(|| format!("read config {}", cfg_path.display()))?;
    let app_cfg: AppConfig = toml::from_str(&raw).context("parse config")?;
    let new_masker = Masker::from_config(&app_cfg.log_masking)
        .context("build masker from reloaded config")?;
    self.masker.store(Arc::new(new_masker));
    tracing::info!("log masking config reloaded");
    Ok(())
}
```

## Watcher Sketch (only if `watch_config_file = true`)
Mirror `crates/waf-engine/src/rules/hot_reload.rs`:
- `notify::recommended_watcher` on `cfg_path`
- On `Modify` event, debounce 500 ms, then call `engine.reload_log_masking(cfg_path)`
- Log failures, never panic, never crash the watcher on parse errors (stale config stays active)

## Concurrency & Safety
- Readers call `self.masker.load()` → `Guard<Arc<Masker>>`, lock-free (ArcSwap).
- Writer (`store`) is also lock-free. Old `Masker` dropped when last reader finishes.
- Failed reload does NOT swap → previous masker stays active → fail-safe (never "accidentally unmask" on bad config).

## Files to Read for Context
- `crates/waf-engine/src/geoip.rs:20-95` — ArcSwap pattern reference
- `crates/waf-engine/src/rules/hot_reload.rs` — notify watcher pattern
- `crates/waf-api/src/handlers.rs:346-349` — existing reload endpoint shape

## Todo
- [ ] Add `reload_log_masking` method on `Engine`
- [ ] Add handler + route `POST /api/log-masking/reload`
- [ ] Protect route with same auth as other admin endpoints (grep existing router layers)
- [ ] (optional) Implement file watcher module + spawn from `main.rs` when enabled
- [ ] Add auth check: only admin role can reload (reuse existing middleware)
- [ ] `cargo check --workspace` + clippy clean
- [ ] Log secret-safe reload messages (do NOT log new denylist contents verbatim — structure may be safe but keep concise)

## Success Criteria
- `curl -X POST /api/log-masking/reload` succeeds after editing config
- Subsequent `attack_logs` rows reflect new denylist without process restart
- Failed reload (bad TOML) returns 500, previous masker still active, next request still masks correctly
- No data race: `cargo test` + `--release` under load does not panic

## Risks
- Config file path must be tracked from startup. `AppState` currently may not hold it — **verify**: if not, add `config_path: Arc<PathBuf>` to `AppState` in Phase 02 or here.
- Watcher on config file that is symlinked (k8s ConfigMap style): use `notify::Config::default().with_poll_interval(...)` fallback. Document as known-issue; not blocking v1.
- Re-parsing full `AppConfig` just for masking is wasteful but safe. Alternative (parse only `[log_masking]` table) is premature optimization — skip per YAGNI.

## Non-Regressions
- Other reload endpoints (`/api/reload`, `/api/rules/reload`) untouched
- `Engine::reload_rules` untouched
- No change to hot path when reload is idle
