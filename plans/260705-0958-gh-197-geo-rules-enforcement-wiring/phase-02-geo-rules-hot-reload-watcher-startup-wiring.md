---
phase: 2
title: "Geo rules hot-reload watcher + startup wiring"
status: completed
priority: P1
dependencies: [1]
effort: "2h"
---

# Phase 2: Geo rules hot-reload watcher + startup wiring

## Overview

Make the Phase 1 loader run: at startup and on every `configs/geo-rules.yaml`
change. Add a `notify`-based `GeoReloader` mirroring `DdosReloader`, an engine
`start_geo_watcher(&self, path)` that does the initial load and holds the
reloader, and one wiring block in `main.rs setup()`. After this phase, admin
CRUD (which writes that file) is enforced with no extra API→engine call.

## Requirements

- Functional: on startup the engine loads existing geo rules; editing/POSTing to
  the file re-loads within the debounce window; deleting the file / bad YAML
  keeps the last good rules (fail-soft) and never blocks startup.
- Non-functional: one background watcher thread (same cost as ddos/tx-velocity),
  no request-path impact.

## Architecture

- New `GeoReloader` in `crates/waf-engine/src/checks/geo_reload.rs`, structurally
  a copy of `crates/waf-engine/src/checks/ddos/reload.rs` (the repo already keeps
  one `spawn_watch` copy per subsystem — access/relay/risk/ddos/tx — so a geo copy
  matches convention; do not attempt a shared abstraction in this issue's scope):
  - `pub fn start(path: PathBuf, geo_check: Arc<GeoCheck>, debounce_ms: u64) -> Result<Self>`
  - reload closure calls the Phase-1 mapping and applies it to `geo_check`
    (reuse the same per-host-load + clear-absent logic; extract a shared
    `apply_geo_rules(&GeoCheck, path)` fn in `geo_config.rs` so both
    `WafEngine::load_geo_rules` and the reloader call one code path — DRY).
  - `const DEFAULT_DEBOUNCE_MS: u64 = 200;` (matches ddos).
- Register `pub mod geo_reload;` + re-export `GeoReloader` in `checks/mod.rs`.
- Engine changes (`crates/waf-engine/src/engine.rs`), mirroring the ddos field:
  - Add field `geo_reloader: OnceLock<GeoReloader>` next to
    `ddos_reloader: OnceLock<DdosReloader>` (`engine.rs:140`); init
    `OnceLock::new()` in the constructor next to `engine.rs:298`.
  - Add `pub fn start_geo_watcher(&self, path: &Path)` next to
    `start_ddos_watcher` (`engine.rs:396`): guard on
    `self.geo_reloader.get().is_some()`, call `self.load_geo_rules(path)` for the
    initial load (Phase 1), then `GeoReloader::start(path.to_path_buf(),
    Arc::clone(&self.geo_check), GEO_DEBOUNCE_MS)` and `set` the `OnceLock`;
    warn-and-continue on watcher start error (exact shape of `start_ddos_watcher`
    at `engine.rs:396-418`).
- `main.rs` wiring (`crates/prx-waf/src/main.rs`), after the tx-velocity block
  (`main.rs:1634`), before the relay block (`main.rs:1636`):
  ```rust
  // Geo restriction subsystem: load configs/geo-rules.yaml and start the
  // hot-reload watcher. The admin API writes the same file, so POST/PATCH/DELETE
  // /api/geoip/rules hot-reloads. Missing/bad file leaves geo_check empty.
  let geo_rules_path = std::path::Path::new(config_file_path)
      .parent()
      .and_then(std::path::Path::parent)
      .unwrap_or_else(|| std::path::Path::new("."))
      .join("configs/geo-rules.yaml");
  engine.start_geo_watcher(&geo_rules_path);
  ```
  This path must equal `geo_api::rules_path` output. Verify: `rules_path`
  (`geo_api.rs:20-31`) uses `main_config_file` → `parent().parent()` →
  `configs/geo-rules.yaml`; `main.rs` uses `config_file_path` → `parent().parent()`
  → `configs/geo-rules.yaml`. Both are the main config file path (e.g.
  `configs/default.toml`), so both resolve to `<root>/configs/geo-rules.yaml`.

## Related Code Files

- Create: `crates/waf-engine/src/checks/geo_reload.rs` (`GeoReloader`, `spawn_watch` copy, tests)
- Modify: `crates/waf-engine/src/checks/mod.rs` (`pub mod geo_reload;` + re-export)
- Modify: `crates/waf-engine/src/checks/geo_config.rs` (extract shared `apply_geo_rules`)
- Modify: `crates/waf-engine/src/engine.rs` (field, ctor init, `start_geo_watcher`, `GEO_DEBOUNCE_MS`)
- Modify: `crates/prx-waf/src/main.rs` (wiring block after `main.rs:1634`)
- Reference: `checks/ddos/reload.rs` (pattern), `engine.rs:396-418` (`start_ddos_watcher`),
  `main.rs:1613-1634` (ddos/tx wiring), `geo_api.rs:20-31` (path agreement)

## Implementation Steps

1. Extract `apply_geo_rules(&GeoCheck, &Path)` in `geo_config.rs`; have
   `WafEngine::load_geo_rules` delegate to it.
2. Add `geo_reload.rs` with `GeoReloader` (copy ddos reloader, swap the reload
   body to `apply_geo_rules`). Register in `checks/mod.rs`.
3. Add engine field + ctor init + `start_geo_watcher`.
4. Add the `main.rs` wiring block; confirm path matches `geo_api::rules_path`.
5. `cargo build -p prx-waf`; `cargo test -p waf-engine geo` (incl. a hot-reload
   swap test mirroring `ddos::reload::tests::hot_reload_swaps_snapshot`).

## Success Criteria

- [ ] Engine loads rules from an existing `geo-rules.yaml` at `start_geo_watcher`.
- [ ] Reloader test: writing a new block rule to the watched file causes a
      subsequent request from that country to be blocked within the debounce +
      poll deadline (mirror the ddos swap test structure).
- [ ] Deleting a rule from the file (rewrite) clears it from `geo_check`.
- [ ] Bad YAML retains the previous rule set (no panic, startup unaffected).
- [ ] `main.rs` geo path is byte-identical in resolution to `geo_api::rules_path`.

## Risk Assessment

- **Path mismatch API↔engine (High if wrong, Low likelihood).** If the two
  resolutions diverge, the watcher watches a file the API never writes → silent
  no-op, the original bug persists. Mitigate: assert equality in an integration
  test (Phase 4) by driving the API `rules_path` and the `main.rs` logic from the
  same `main_config_file` and comparing.
- **notify debounce flakiness in tests (Med).** Use the ddos test's poll-until-
  deadline pattern, not a fixed sleep. Prefer the deterministic
  `WafEngine::load_geo_rules` path (Phase 1) for the enforcement acceptance test;
  keep the watcher swap test scoped to the reloader module.
- **Reload race on concurrent CRUD (Low here, owned by GH-203).** Full-snapshot
  replace per load; a rapid create-then-delete could reload an intermediate file
  state, but each load is internally consistent. The reload-guard hardening is
  explicitly GH-203's scope; note the boundary, do not implement it here.
</content>
