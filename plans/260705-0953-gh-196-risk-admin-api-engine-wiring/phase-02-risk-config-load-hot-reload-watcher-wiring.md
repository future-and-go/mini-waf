---
phase: 2
title: "Risk config load + hot-reload watcher wiring"
status: completed
priority: P1
dependencies: [1]
---

# Phase 2: Risk config load + hot-reload watcher wiring

## Overview

Add `WafEngine::start_risk_watcher(&self, path)` mirroring
`start_rate_limit_watcher` / `start_ddos_watcher` / `start_tx_velocity_watcher`,
and call it from `main.rs` `setup()`. After this phase, `PUT /api/risk/config`
takes effect without restart.

## Requirements

- Functional: startup loads `configs/risk.yaml`; file edits (including API PUT)
  hot-reload within the debounce window; canary layer stays in sync.
- Non-functional: fail-soft — missing/bad file logs a warning and leaves the
  subsystem at defaults (disabled); the gateway never refuses to start.

## Architecture

- `start_risk_watcher(&self, path: &Path)`:
  1. Guard with `OnceLock` reloader field (`risk_reloader: OnceLock<RiskReloader>`),
     same as `rate_limit_reloader` (`engine.rs` field block).
  2. Initial load: `RiskConfig::from_path(path)`; on Ok — build store + scorer
     from Phase 1 helpers, swap `self.scorer`, then `replace_risk_config(cfg)`.
  3. Start the watcher. **Reload callback must run `replace_risk_config`
     semantics** (canary paths + ban TTL resync, `risk_cfg` swap), not
     `RiskReloader`'s raw ArcSwap store. Generalize `RiskReloader::start` to
     accept an `on_change: impl Fn(RiskConfig)` callback (its current
     ArcSwap-specific signature has zero production callers, so the signature
     is free to change; keep the existing reload tests by adapting them).
  4. On reload, if `store.backend` differs from the active store, keep the
     active store and `warn!("risk store backend change requires restart")`
     (Key Decision: backend is start-time only).
- `main.rs` `setup()` (~after `engine.start_tx_velocity_watcher` call, line
  ~1634): resolve `configs/risk.yaml` the same way ddos/tx-velocity paths are
  resolved and call `engine.start_risk_watcher(&risk_path)`.

## Related Code Files

- Modify: `crates/waf-engine/src/risk/reload.rs` (callback generalization)
- Modify: `crates/waf-engine/src/engine.rs` (`start_risk_watcher`, reloader field)
- Modify: `crates/prx-waf/src/main.rs` (setup wiring; both engine construction
  sites if the second one at line ~1025 serves traffic — verify which path is live)

## Implementation Steps

1. Generalize `RiskReloader::start` to take a callback; adapt its two unit tests.
2. Add `risk_reloader: OnceLock<RiskReloader>` engine field + `start_risk_watcher`.
3. Wire `main.rs` setup; confirm path resolution matches what `waf-api` writes
   (`resolve_path(&state, "configs/risk.yaml")` — same root).
4. Manual smoke: start gateway with `risk.enabled: true` fixture, confirm
   `X-WAF-Risk-Score` header appears (emit_header default true).

## Success Criteria

- [ ] Engine test: `start_risk_watcher` + file write → `risk_cfg` snapshot and
      canary paths update (reuse `reload_swaps_snapshot_on_file_change` shape).
- [ ] Bad YAML on reload keeps previous snapshot (existing fail-soft test shape).
- [ ] `main.rs` calls `start_risk_watcher` in the production setup path.

## Risk Assessment

- Two `WafEngine::new` sites exist in main.rs (~1025, ~1596); wire the one(s)
  actually serving traffic — check before assuming.
- Watcher path must be the identical file the API writes, or PUT will "work"
  in tests and miss in prod (root resolution differs per deploy layout).
