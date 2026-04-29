# Phase 4 — Config Watcher (Hot-Reload)

## Context
- Design doc §8 (hot-reload mechanics).
- Existing pattern to follow: `crates/waf-engine/src/rules/hot_reload.rs` (notify-based).

## Why
Hot-reload satisfies the spirit of FR-031 ("update config — NO service restart"). Reusing the rules-engine pattern keeps cognitive surface small. Junior trap: implementing watcher inside the registry — couples I/O concerns to data concerns. Keep them separate.

## Goals
- Watch `configs/default.toml` for changes (or a configurable path).
- On change → parse → validate → build snapshot → `registry.swap()`.
- On parse/validate error → log warn, keep old snapshot, do NOT panic.
- Debounce rapid edits (editors save in 2-3 bursts).

## Files
- **Create:** `crates/gateway/src/tiered/tier_config_watcher.rs`
- **Modify:** `crates/gateway/src/tiered/mod.rs`

## Implementation Notes

### Reuse rules-engine pattern
First read `crates/waf-engine/src/rules/hot_reload.rs` to mirror:
- `notify::RecommendedWatcher` + `EventKind::Modify`
- Tokio task that consumes events, debounces, reloads
- Graceful shutdown via `CancellationToken` or `oneshot::Receiver`

### API
```rust
pub struct TierConfigWatcher { /* opaque handle */ }

impl TierConfigWatcher {
    /// Spawn a background task that watches `path` and applies changes to `registry`.
    pub fn spawn(
        path: PathBuf,
        registry: Arc<TierPolicyRegistry>,
        shutdown: CancellationToken,
    ) -> Result<Self, WatcherError>;
}
```

### Reload flow
```
file event → debounce 200ms → fs::read_to_string → toml::from_str
    → TierConfig::validate → TierSnapshot::try_from_config → registry.swap
    → tracing::info!(tier_count, rule_count, "tier config reloaded")
```
On any error in this chain: `tracing::warn!(?err, "tier config reload failed; keeping previous")`.

### Path scoping
TOML may host other tables. Strategy: parse the whole file, then extract `[tiered_protection]` table. If absent → log warn, keep previous. WHY: lets ops edit other parts of config without false-failing tier reload.

## Tests
- Integration test in `crates/gateway/tests/tier_hot_reload.rs`:
  - Write valid TOML to tempdir, spawn watcher, assert initial policy.
  - Overwrite with new threshold, sleep 300ms, assert new policy active.
  - Overwrite with malformed TOML, assert old policy still active + warning logged (use `tracing-test`).

## Acceptance
- Integration test green.
- No `.unwrap()` in production code paths (per CLAUDE.md).
- File < 200 LoC.

## Common Pitfalls
- Forgetting to debounce → editors trigger 2-3 events per save → 3 reloads per edit.
- Panic on bad TOML → kills proxy. Always `?` + `warn!`.
- Watching dir vs file → file replacement (some editors rename-then-write) drops the inode being watched. Solution: watch parent dir, filter on file name.
- Holding `Arc<TierPolicyRegistry>` and `Arc<TierSnapshot>` confused — registry is the swap point, snapshot is the value being swapped.

## Todo
- [x] Read existing `rules/hot_reload.rs` for pattern
- [x] `tier_config_watcher.rs` with `spawn()`
- [x] Debounce (`recv_timeout` + `last_event.elapsed() >= debounce`, default 200ms)
- [x] Watch parent dir, filter file name
- [x] Integration test (4 scenarios: swap, malformed, missing-section, live watcher)

## Deviations from plan
- Used `std::thread` + sync `mpsc` (mirroring existing `rules/hot_reload.rs`) instead of tokio task + `CancellationToken`. Plan suggested both; chose pattern reuse over the alternative. Drop the watcher to stop.
- Made `reload()` `pub` (was `pub(crate)`) so the integration test can drive the chain synchronously without polling.

## Next
Phase 5 — wire registry into request lifecycle.
