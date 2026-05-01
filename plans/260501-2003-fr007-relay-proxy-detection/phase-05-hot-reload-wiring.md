# Phase 05 — Hot-Reload Wiring (notify + ArcSwap)

## Context Links
- Design: brainstorm §4.7
- Reuse verbatim: `crates/waf-engine/src/access/reload.rs` (FR-008 watcher)

## Overview
**Priority:** P0 · **Status:** completed · **Effort:** 0.5 d

Wire `notify` filesystem watcher to ArcSwap pointers for `RelayConfig`, `TorSet`, `AsnDb`. File change → rebuild snapshot → `ArcSwap::store(Arc<new>)`. ≤1s propagation, no service restart, no in-flight request drop.

## Key Insights
- One watcher process can monitor multiple paths; debounce 200ms to coalesce editor save bursts.
- Each watched path has a typed reload fn: `reload_config(path) -> Result<RelayConfig>`, `reload_tor(path) -> Result<TorSet>`, `reload_asn(path) -> Result<Box<dyn AsnDb>>`.
- Reload failure → log WARN + keep prior snapshot. NEVER swap to a broken snapshot (FR-008 AC-07 pattern).
- Refresh tasks (phase-04) write atomic rename → watcher receives `Modify` → reload triggers ArcSwap.
- Single `Arc<ArcSwap<RelayDetectorState>>` aggregating cfg + tor_set + asn_db keeps providers reading one pointer; alternative is per-pointer ArcSwap. **Choose per-pointer**: tor refresh shouldn't churn config readers.

## Requirements

### Functional
- `RelayReloader::start(paths: ReloadPaths, swaps: ReloadSwaps) -> Result<JoinHandle>`.
- 200ms debounce per path.
- On `RelayConfig` change: rebuild config + reconstruct registry (new providers per `signals.enabled`) + swap `Arc<RelayDetectorState>`.
- On `TorSet` file change: load new set + swap `Arc<ArcSwap<TorSet>>`.
- On `AsnDb` file change: open new DB + swap `Arc<ArcSwap<dyn AsnDb>>`.
- Failure path: WARN log, keep prior pointer, no swap.

### Non-functional
- ≤1s from file write to next request observing new value (CI test target 500ms).
- No alloc on read path (ArcSwap `load()` is RCU-style).
- File ≤200 LOC.

## Architecture

```
RelayDetector (long-lived)
├── cfg:     Arc<ArcSwap<RelayConfig>>
├── registry: Arc<ArcSwap<ProviderRegistry>>   ── rebuilt on cfg reload
├── tor_set: Arc<ArcSwap<TorSet>>
└── asn_db:  Arc<ArcSwap<dyn AsnDb>>

RelayReloader
└── notify::RecommendedWatcher → debounce → typed reload fn → ArcSwap::store
```

Providers hold cloned `Arc<ArcSwap<T>>`; on each `evaluate` call: `let snap = self.tor_set.load();` (cheap).

## Related Code Files

### Create
- `crates/waf-engine/src/relay/reload.rs` — `RelayReloader` w/ notify integration

### Modify
- `crates/waf-engine/src/relay/mod.rs` — `RelayDetector::with_reloader(paths) -> Result<Self>` constructor
- `crates/waf-engine/src/relay/registry.rs` — make `ProviderRegistry` rebuildable from `(RelayConfig, &shared deps)`
- `crates/waf-engine/src/relay/providers/{xff_validator,proxy_chain,asn_classifier,tor_exit}.rs` — accept Arc-shared snapshots in constructors

### Reuse
- `crates/waf-engine/src/access/reload.rs` — copy debounce + watcher-spawn pattern; do NOT duplicate watcher infra wholesale, extract shared helper if needed (KISS — copy if <40 lines, extract if more)

## Implementation Steps

1. **`reload.rs::ReloadPaths`** — struct holding `config_path`, `tor_list_path`, `asn_mmdb_path` (all `Option<PathBuf>` for air-gap / disabled features).
2. **`reload.rs::ReloadSwaps`** — `Arc<ArcSwap<RelayConfig>>`, `Arc<ArcSwap<TorSet>>`, `Arc<ArcSwap<dyn AsnDb>>`.
3. **`RelayReloader::start`**:
   - Build `notify::RecommendedWatcher` w/ `Config::default().with_poll_interval(...)` if needed.
   - Watch each Some-path with `RecursiveMode::NonRecursive`.
   - Spawn tokio task: receive events → debounce 200ms → match path → call typed reload fn → on Ok call `swap.store(Arc::new(new))`; on Err log WARN.
4. **Per-path reload functions** — small typed wrappers calling phase-01..04 builders.
5. **`RelayDetector::with_reloader(paths) -> Result<Self>`** — initial load (sync) + start reloader task. Initial load failure on CRITICAL feed is fail-close (per phase-03 §Q2).
6. **Provider construction** — each provider receives its needed `Arc<ArcSwap<T>>` clone; `evaluate` does `load()` per call (RCU, ~ns cost).
7. **Registry rebuild on config reload** — when `RelayConfig` changes, `ProviderRegistry::from_config(&new_cfg, &shared_arcswaps)` constructs fresh `Vec<Box<dyn SignalProvider>>` and `ArcSwap::store`.
8. **Test**: tempfile → write → assert ArcSwap content updated within 1s (full integration in phase-07).

## Todo List
- [x] `ReloadPaths` + `ReloadSwaps` structs
- [x] `RelayReloader::start` w/ notify + debounce
- [x] Per-path typed reload fns (`reload_config`, `reload_tor`, `reload_asn`)
- [ ] `RelayDetector::with_reloader` constructor — deferred to phase-06 (gateway lifecycle)
- [ ] Registry rebuild on cfg reload — deferred to phase-06 (cfg ArcSwap is wired; registry rebuild plumbs into gateway)
- [ ] Providers accept Arc-shared snapshots — already true for `TorExitMatcher` + `AsnClassifier`; xff/proxy_chain rebuild plumbed in phase-06
- [x] Smoke test: write file → ArcSwap updated within 1s
- [x] `cargo check` + clippy clean

## Success Criteria
- Smoke test: edit YAML → within 1s `cfg.load().max_chain_depth` reflects new value.
- Smoke test: append IP to tor list → within 1s `TorExitMatcher` matches it.
- Smoke test: malformed YAML write → prior config still active, WARN logged.
- File LOC ≤200.

## Common Pitfalls
- `notify` on Linux uses inotify; editor "atomic save" (write-tmp + rename) fires `Create` not `Modify` — handle both.
- Debounce must be per-path, not global (else editing config while tor list refresh fires drops one event).
- `ArcSwap::store` accepts `Arc<T>` not `T` — wrap fresh snapshot.
- Forgetting to drop old `Arc` references → memory grows; `ArcSwap` handles this automatically via RCU.

## Risk Assessment
Medium — reload-while-reload race could leak handle. Mitigated by single-task model (one reloader, sequential per path).

## Security Considerations
- Watch only operator-owned paths (config + intel feed targets); never user-uploaded.
- Reload failure does not crash service (FR-036 graceful-degradation).

## Next Steps
Phase 06 — gateway integration: `RelayDetector::evaluate` in `proxy.rs`, attach `ClientIdentity`, rule predicate hooks, risk-scorer wiring.
