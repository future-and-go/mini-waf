# Phase 06 — Hot-Reload Watcher

## Context Links
- Design: brainstorm §4 (reload module), D8
- Reference impl: `crates/gateway/src/tiered/tier_config_watcher.rs`

## Overview
**Priority:** P0 · **Status:** complete · **Effort:** 0.5 d

`notify::RecommendedWatcher` + SIGHUP signal both trigger an atomic `ArcSwap` of `Arc<AccessLists>`. On parse failure, the previous snapshot is retained and a structured WARN is emitted — the gateway never crashes from a bad config.

## Key Insights
- **Observer pattern**: file-system event source pushes; ArcSwap is the synchronisation primitive between writer and lock-free readers.
- Identical pattern already in tier config watcher — copy the structure to keep the codebase consistent.
- Debounce is needed: editors emit multiple events per save (truncate + write). 250 ms window is the existing FR-002 default.

## Requirements

### Functional
- `AccessReloader::spawn(path, store)` returns a `JoinHandle` that:
  - Watches `path` for `Modify` and `Create` events.
  - On event (debounced 250 ms): re-parse via `AccessLists::from_yaml_path(path)`.
  - On `Ok(new)` → `store.store(new)` (ArcSwap atomic swap) + `tracing::info!("access lists reloaded")`.
  - On `Err(e)` → keep prior snapshot + `tracing::warn!(error=?e, "access reload failed")`.
- Optional SIGHUP listener (Unix only): same reload routine.
- Graceful shutdown via dropped `JoinHandle` / cancellation token.

### Non-functional
- Reload latency from file save → live: < 1 s (NFR §8 item 8).
- Zero dropped requests during swap (covered by ArcSwap semantics + e2e test in phase-07).

## Architecture

```
fs event ──notify──┐
                   ├──debounce 250 ms──► reload_once(path)
SIGHUP    ──signal─┘                          │
                                              ├── parse OK   → ArcSwap.store(new)
                                              └── parse FAIL → log WARN, keep prior
```

## Related Code Files

### Create
- `crates/waf-engine/src/access/reload.rs` — `AccessReloader` (spawning, watcher loop)

### Modify
- `crates/waf-engine/src/access/mod.rs` — `pub use reload::AccessReloader;`
- `crates/gateway/src/proxy.rs` — when `with_access_lists` is set and a path is provided, spawn the reloader during `Proxy::start` (or wherever tier reloader is spawned today).

## Implementation Steps

1. **Read** `tier_config_watcher.rs` end-to-end. Mirror its module structure: same channel types, same debounce constant, same shutdown mechanism. Copying conventions reduces review surface and incidents.
2. **Create** `access/reload.rs`:
   ```rust
   use std::path::PathBuf;
   use std::sync::Arc;
   use std::time::Duration;

   use arc_swap::ArcSwap;
   use notify::{RecommendedWatcher, RecursiveMode, Watcher};
   use tokio::sync::mpsc;
   use tokio::task::JoinHandle;

   use super::AccessLists;

   const DEBOUNCE: Duration = Duration::from_millis(250);

   pub struct AccessReloader;

   impl AccessReloader {
       pub fn spawn(path: PathBuf, store: Arc<ArcSwap<Arc<AccessLists>>>) -> anyhow::Result<JoinHandle<()>> {
           let (tx, mut rx) = mpsc::unbounded_channel::<()>();
           let mut watcher: RecommendedWatcher = notify::recommended_watcher(move |res| {
               if let Ok(_event) = res { let _ = tx.send(()); }
           })?;
           watcher.watch(&path, RecursiveMode::NonRecursive)?;

           let handle = tokio::spawn(async move {
               let _w = watcher; // keep watcher alive
               loop {
                   if rx.recv().await.is_none() { break; }
                   tokio::time::sleep(DEBOUNCE).await;
                   while rx.try_recv().is_ok() {} // drain coalesced events
                   match AccessLists::from_yaml_path(&path) {
                       Ok(new) => {
                           store.store(Arc::new(new.as_ref().clone_arc()));
                           tracing::info!(path=?path, "access lists reloaded");
                       }
                       Err(e) => tracing::warn!(error=?e, path=?path, "access reload failed"),
                   }
               }
           });
           Ok(handle)
       }
   }
   ```
   *(`AccessLists` is already `Arc<Self>` from phase-01; the `clone_arc` helper just clones the Arc — see step 3.)*

3. **Helper** on `AccessLists`:
   ```rust
   impl AccessLists {
       /// Identity Arc-clone helper used by the reloader so callers don't reach
       /// into private fields.
       pub fn arc_clone(self: &Arc<Self>) -> Arc<Self> { Arc::clone(self) }
   }
   ```
   (Or reshape `from_yaml_path` to return `Arc<Self>` already, which matches phase-01 plan — easier.) Goal: reload code is one line.
4. **SIGHUP** (optional, Unix-only — gate behind `#[cfg(unix)]`): `tokio::signal::unix::signal(SignalKind::hangup())` listener that emits the same `()` event into the same channel. Keep it inside `reload.rs` so all reload triggers live in one module.
5. **Wire-up in `Proxy`**: add `pub fn start_access_reloader(&self, path: PathBuf) -> anyhow::Result<JoinHandle<()>>` — caller `main.rs` invokes after `with_access_lists`.
6. **Tests** (integration — phase-07 will repeat these as tagged ACs):
   - `t_reload_swap`: write file v1, init, assert state v1; write v2 to disk; sleep 350 ms; assert ArcSwap.load() reflects v2.
   - `t_reload_bad_yaml_keeps_prior`: write malformed; sleep; assert ArcSwap.load() unchanged + WARN log captured.

## Todo List
- [x] Read existing tier_config_watcher.rs to mirror its conventions
- [x] Implement `AccessReloader::spawn`
- [x] `from_yaml_path` already returns `Arc<Self>` (phase-01) — reload is one-line `store.store(new)`
- [x] SIGHUP listener (`#[cfg(unix)]`) — `spawn_sighup_listener`
- [~] Wire reload spawn into `Proxy` — deferred: tier watcher itself is not yet wired in `main.rs`; public API exposed via `AccessReloader::spawn` for symmetric wiring later
- [x] 2 integration tests (`tests/access_hot_reload.rs`)
- [x] `cargo check --workspace` clean + `cargo clippy -p waf-engine -- -D warnings`

## Success Criteria
- AC-07 passes: malformed YAML → previous snapshot retained + WARN emitted (no panic).
- AC-08 passes: live request stream unaffected by swap (verified in phase-07 e2e under load).
- File ≤ 200 LoC.

## Common Pitfalls
- **Watcher dropped early**: `RecommendedWatcher` must outlive the spawned task. `let _w = watcher;` inside the spawned future keeps it alive.
- **No debounce**: editors emit 2-5 events per save. Without debounce, you re-parse 5× per save.
- **`unwrap()` in async task body**: BANNED. Use `if let Ok` / `match` / `?` only when the function returns `Result`.
- **Calling `from_yaml_path` while writer mid-write**: file may be empty for a few ms. Parser already returns `Err` — caught by AC-07 path.

## Risk Assessment
- Low–medium. Pattern is proven (FR-002, FR-003 reuse). Risks are timing-related and covered by tests.

## Security Considerations
- Reload reads from a static, deployer-controlled path — no user input.
- Bad YAML cannot crash the gateway (AC-07).
- SIGHUP on Unix is privileged — same trust boundary as the file itself.

## Next Steps
- Phase 07: comprehensive tests + bench + coverage gate.
