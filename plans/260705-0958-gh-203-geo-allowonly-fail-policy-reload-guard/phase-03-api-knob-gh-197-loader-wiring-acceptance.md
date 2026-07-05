---
phase: 3
title: "API knob + GH-197 loader wiring + acceptance"
status: completed
dependencies: [1, 2]
effort: "1.5h"
---

# Phase 3: API knob + GH-197 loader wiring + acceptance

## Overview

Expose the fail-closed policy through the admin API row shape and map it into the
engine `GeoRule.fail_closed` (added in Phase 2) via GH-197's loader. Then add the
acceptance tests the issue requires. This phase **depends on GH-197 having
merged** (it edits `checks/geo_config.rs`, `GeoRuleRow`, `parse_geo_rules`) and on
Phase 2 (`GeoRule.fail_closed` exists).

## Requirements

- Functional: `create_geo_rule` / `patch_geo_rule` (`geo_api.rs:82-131`) accept
  and persist an optional `fail_closed` bool on `action:"allow"` rows.
- Functional: GH-197's `parse_geo_rules` reads `fail_closed` from allow rows and
  sets the host's single AllowOnly `GeoRule.fail_closed` via OR aggregation (any
  enabled allow row `true` → rule fail-closed).
- Functional: absent `fail_closed` → `false` (fail-open — unchanged), so existing
  persisted rules and API clients are unaffected.
- Functional: `fail_closed` on a `block` row is ignored (no effect on Block rules).

## Architecture

### 1. API persistence (`geo_api.rs`)

- `create_geo_rule` (`geo_api.rs:82-105`): add `fail_closed` to the `new_rule`
  object, read from body, default `false`:
  `"fail_closed": body.get("fail_closed").and_then(Value::as_bool).unwrap_or(false)`.
  Keep it in the row for all actions (harmless on block rows; loader only reads it
  for allow rows) — simplest, avoids conditional shape.
- `patch_geo_rule` (`geo_api.rs:120-126`): add `"fail_closed"` to the mutable
  field allow-list alongside `enabled`/`action`/`scope`.
- No response-envelope change; `fail_closed` rides in `data` like other fields.
  The API is a pass-through JSON store, so this is additive and back-compatible.

### 2. Loader mapping (GH-197 `checks/geo_config.rs`)

- Extend `GeoRuleRow` (GH-197 phase-1, its lines ~39-47) with
  `#[serde(default)] fail_closed: bool`.
- In `parse_geo_rules`' per-host grouping, while unioning **allow** rows, OR their
  `fail_closed` into a per-host accumulator. Emit the host's `AllowOnly` `GeoRule`
  with `fail_closed: <accumulated>`. Block rule emitters set `fail_closed: false`.
- Re-verify GH-197's exact struct/function shape at implementation time
  (`rg -n "GeoRuleRow|parse_geo_rules|fail_closed" crates/waf-engine/src/checks/geo_config.rs`);
  the field names above mirror GH-197's plan but must match its merged code.

## Related Code Files

- Modify: `crates/waf-api/src/geo_api.rs` — `create_geo_rule` (82-105),
  `patch_geo_rule` (120-126).
- Modify: `crates/waf-engine/src/checks/geo_config.rs` (GH-197-owned; add
  `fail_closed` to row + OR into AllowOnly rule).
- Add tests: `geo_config.rs` mapping tests; `geo_api.rs` round-trip test;
  acceptance test (engine crate integration or `tests/`).
- Reference: `GeoRule.fail_closed` (Phase 2, `geo.rs:23-31`); one-AllowOnly-rule-
  per-host mapping (GH-197 phase-1 Key Decisions).

## Implementation Steps

1. Add `fail_closed` persistence to `create`/`patch` geo-rule handlers.
2. Add `fail_closed` to `GeoRuleRow`; OR it into the host AllowOnly rule in
   `parse_geo_rules`.
3. Loader unit test: two allow rows for one host, one with `fail_closed:true` →
   the emitted AllowOnly rule is `fail_closed:true` (OR); both false → false.
4. API test: POST allow rule with `fail_closed:true` → GET/read-back shows it;
   PATCH toggles it.
5. Acceptance (end-to-end): write an allow rule with `fail_closed:true` to
   `configs/geo-rules.yaml` → `engine.load_geo_rules` (GH-197) → a request whose
   `ctx.geo` is empty/absent for that host is blocked by `Phase::GeoIp`; repeat
   with `fail_closed:false` → request passes. Reuse GH-197's acceptance harness
   pattern (its Phase 4).
6. `cargo test -p waf-engine geo`; `cargo test -p waf-api geo`;
   `cargo clippy --workspace --all-targets`; `cargo fmt --check`.

## Success Criteria

- [ ] POST `/api/geoip/rules` with `action:"allow", fail_closed:true` persists the
      field; GET returns it; PATCH toggles it.
- [ ] `parse_geo_rules`: one host, two allow rows, one `fail_closed:true` → emitted
      AllowOnly rule is `fail_closed:true` (OR aggregation).
- [ ] `parse_geo_rules`: all allow rows `fail_closed:false` (or absent) → emitted
      AllowOnly rule `fail_closed:false`.
- [ ] `fail_closed` on a block row does not make any Block rule fail-closed.
- [ ] End-to-end: allow rule `fail_closed:true` + request with empty geo → blocked;
      same rule `fail_closed:false` → allowed.

## Risk Assessment

- **Depends on GH-197 merge (High for scheduling).** Editing `geo_config.rs`
  before GH-197 lands would conflict. Mitigation: `blockedBy` on GH-197 enforces
  order; re-grep the merged `geo_config.rs` shape before editing (names may drift
  from GH-197's plan).
- **OR-aggregation surprise (Low).** One fail-closed allow row flips the whole
  host allowlist to fail-closed. Documented "most-restrictive wins"; covered by
  the OR unit test. Open Question flags whether operators want per-host explicit
  control instead.
- **API back-compat (Low).** Field is additive with a `false` default; existing
  rows/clients unaffected. Verified `geo_api.rs` is a pass-through JSON store.
- **Rollback:** drop `fail_closed` from the API handlers and `GeoRuleRow`; rules
  map to `fail_closed:false` (fail-open) — safe degrade to current behavior.
</content>
