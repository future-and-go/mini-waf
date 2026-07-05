---
phase: 1
title: "Shared geo rule schema + engine loader/mapping"
status: pending
priority: P1
dependencies: []
effort: "2h"
---

# Phase 1: Shared geo rule schema + engine loader/mapping

## Overview

Add an engine-side loader that reads the admin API's `configs/geo-rules.yaml`
row shape and maps it to the engine's `Vec<GeoRule>`, grouped per host, then
loads it into `GeoCheck`. No wiring yet (Phase 2) — this phase delivers the pure
parse + map + load unit, fully unit-testable without a running server.

## Requirements

- Functional: given the file the API writes
  (`{rules: [{id, iso_code, action, scope, enabled, country_name}]}`), produce
  the geo rules the engine enforces, grouped by host code, with block and allow
  rows each unioned into one rule.
- Functional: `enabled:false` rows are skipped; missing/absent file is fail-soft
  (loads an empty set, logs a warning — never panics, never refuses).
- Non-functional: mapping is allocation-modest and does not touch the request
  hot path (load-time only).

## Architecture

- New module `crates/waf-engine/src/checks/geo_config.rs`, registered in
  `crates/waf-engine/src/checks/mod.rs` (`pub mod geo_config;`) with re-exports.
  Rationale for a sibling file (not converting `geo.rs` to a folder): keeps the
  ~300-line evaluation module + its tests untouched (surgical), and the loader is
  a distinct concern (<200 lines).
- Deserialize struct mirroring the API row shape:
  ```rust
  #[derive(Debug, Clone, serde::Deserialize)]
  struct GeoRuleRow {
      iso_code: String,
      #[serde(default = "default_action")] action: String,   // "block" | "allow"
      #[serde(default = "default_scope")]  scope:  String,    // "global" | <host code>
      #[serde(default = "default_enabled")] enabled: bool,
      #[serde(default)] country_name: Option<String>,
      #[serde(default)] id: Option<i64>,
  }
  #[derive(serde::Deserialize)] struct GeoRulesFile { #[serde(default)] rules: Vec<GeoRuleRow> }
  ```
  `id`/`country_name` are optional (name is derived; the API sets both but the
  loader must not hard-fail if absent).
- `pub fn parse_geo_rules(path: &Path) -> anyhow::Result<HashMap<String, Vec<GeoRule>>>`:
  read file → `serde_yaml::from_str::<GeoRulesFile>` → group rows.
  - Host key: `scope == "global"` → `"*"`, else `scope`.
  - Within a host, collect block `iso_code`s into one `HashSet` and allow
    `iso_code`s into another (uppercased at map time; `GeoCheck::load_rules`
    also uppercases, but do it here so the grouping key/set is canonical).
  - Emit at most one `GeoRule{ mode: Block, iso_codes: <block set>, countries: {}, id, name }`
    and one `GeoRule{ mode: AllowOnly, iso_codes: <allow set>, ... }` per host,
    only when the corresponding set is non-empty. `countries` stays empty (the
    API captures ISO codes, not free-text country names; `country_name` is a UI
    label only). Skip `enabled == false` rows before grouping.
  - Rule `id`: stable synthetic string per (host, mode), e.g. `"geo-{host}-block"` /
    `"geo-{host}-allow"`; `name`: derive from mode (`"Geo block"` / `"Geo allow-only"`).
    Do NOT embed plan/issue IDs (repo rule). Keep the string human-meaningful.
- `impl WafEngine { pub fn load_geo_rules(&self, path: &Path) }`
  (add to `crates/waf-engine/src/engine.rs`, near the other loaders):
  - `parse_geo_rules(path)` → on `Ok(map)`: for each `(host, rules)` call
    `self.geo_check.load_rules(&host, rules)`; then `clear_rules` for any host
    previously loaded but absent now (track loaded host keys — Phase 2's reloader
    re-invokes this, so absent-host clearing prevents stale rules surviving a
    delete). On `Err`: `warn!` and leave existing rules in place (fail-soft;
    matches ddos "keep previous snapshot").
  - To track previously-loaded hosts across reloads without a diff, simplest
    correct approach: snapshot the current host-key set inside `GeoCheck`
    (`GeoCheck::loaded_hosts() -> Vec<String>`) and clear those not in the new
    map. Add a tiny `GeoCheck::loaded_hosts()` reading `self.rules` keys if not
    already derivable — verify against `checks/geo.rs:53` (`rules: Arc<DashMap>`).

## Related Code Files

- Create: `crates/waf-engine/src/checks/geo_config.rs` (rows, `parse_geo_rules`, tests)
- Modify: `crates/waf-engine/src/checks/mod.rs` (`pub mod geo_config;` + re-export at ~line 10/35)
- Modify: `crates/waf-engine/src/engine.rs` (add `load_geo_rules(&self, path)`)
- Modify: `crates/waf-engine/src/checks/geo.rs` only if a `loaded_hosts()` helper
  is needed for absent-host clearing (`GeoCheck` at line 51-84)
- Reference (do not change): API row shape `geo_api.rs:92-100`; `GeoRule`/`GeoRuleMode`
  `checks/geo.rs:23-40`; `load_rules` `checks/geo.rs:68`; `clear_rules` `checks/geo.rs:82`

## Implementation Steps

1. Add `geo_config.rs` with `GeoRuleRow`/`GeoRulesFile` + `parse_geo_rules`.
2. Register module + re-export `parse_geo_rules` in `checks/mod.rs`.
3. Add `GeoCheck::loaded_hosts()` if needed for absent-host clearing.
4. Add `WafEngine::load_geo_rules(&self, path)` calling parse → per-host
   `load_rules` + clear absent hosts, fail-soft.
5. Unit tests in `geo_config.rs` (see Success Criteria); `cargo test -p waf-engine geo`.

## Success Criteria

- [ ] `parse_geo_rules` maps a block row `{iso_code:"KP", action:"block", scope:"global"}`
      to one `GeoRule{mode:Block, iso_codes:{"KP"}}` under host `"*"`.
- [ ] Two block rows for the same host union into a single Block rule's `iso_codes`.
- [ ] Two allow rows union into a single `AllowOnly` rule (not two rules) —
      the mapping that pre-empts GH-203's multi-allow footgun.
- [ ] `enabled:false` rows are excluded from the mapped set.
- [ ] `scope:"example"` maps under host key `"example"`, not `"*"`.
- [ ] Missing file → `Err` handled by `load_geo_rules` as fail-soft (no panic);
      empty `rules:` list → empty map.
- [ ] `load_geo_rules` clears rules for a host that disappears between two loads.

## Risk Assessment

- **Case sensitivity of iso codes (Low).** `load_rules` already uppercases; map
  side uppercasing is belt-and-suspenders. Verified `checks/geo.rs:68-79`.
- **Absent-host clearing correctness (Med).** If not cleared, a deleted rule
  survives in `geo_check` until restart — the exact bug class this issue is about.
  Unit-test the two-load delete path explicitly.
- **`countries` left empty (Low).** The API has no free-text country field
  (`geo_api.rs` stores `iso_code` + display `country_name`); matching is ISO-only,
  consistent with how the admin UI creates rules. Documented, not a regression.
</content>
