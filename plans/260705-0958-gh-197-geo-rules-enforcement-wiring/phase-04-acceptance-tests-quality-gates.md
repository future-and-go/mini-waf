---
phase: 4
title: "Acceptance tests + quality gates"
status: pending
priority: P1
dependencies: [1, 2, 3]
effort: "2h"
---

# Phase 4: Acceptance tests + quality gates

## Overview

Prove the issue's acceptance criteria end to end and run the workspace gates.
The headline test is the issue's own line: create a block rule via the API path →
a request from that country is blocked. Depends on all prior phases.

## Requirements

- The four issue acceptance-criteria checkboxes are each covered by a test.
- No flaky reliance on `notify` timing in the enforcement assertion (use the
  deterministic `WafEngine::load_geo_rules` path; keep watcher timing in the
  Phase-2 reloader unit test).
- All gates green: `cargo test` (touched crates), `clippy`, `fmt`.

## Architecture / Test Matrix

| Criterion | Level | Where |
| --- | --- | --- |
| Shared schema / mapping (block union, allow union, disabled skip, scope→host, delete-clears) | unit | `checks/geo_config.rs` (Phase 1) |
| File change → rules applied (hot-reload swap; bad YAML retained) | unit/integration | `checks/geo_reload.rs` (Phase 2) |
| Startup loads existing file into `geo_check` | integration | `crates/waf-engine/tests/geo_rules_enforcement.rs` (new) |
| **Create block rule via API → request from that country blocked** | integration | new engine test + API handler test (below) |
| `lookup_ip` real vs stub fallback | integration | `crates/waf-api/tests/handler_geo_rules.rs` (new) |

- **Enforcement acceptance (engine-level, deterministic).** New
  `crates/waf-engine/tests/geo_rules_enforcement.rs`:
  1. Write a `geo-rules.yaml` in a `tempfile::tempdir()` with the API's exact row
     shape (`{rules: [{id:1, iso_code:"KP", action:"block", scope:"global",
     enabled:true, country_name:"North Korea"}]}`).
  2. Build a `WafEngine` (reuse the fixture helper used by `engine_lifecycle.rs`),
     call `engine.load_geo_rules(&path)`.
  3. Assert `engine.geo_check().check(&mut ctx)` is `Some(..)` for a `KP` ctx and
     `None` for `US` (build ctx like `checks/geo.rs` tests `make_ctx`, with
     `geo: Some(GeoIpInfo{iso_code:"KP",..})`). This is the issue's headline
     assertion, exercised through the real file→map→load path.
  4. Second load with the rule removed (rewrite file to `{rules: []}`) →
     `check` returns `None` (delete is enforced, absent-host clear works).
  5. AllowOnly case: two allow rows (`US`, `CA`) → a `CA` ctx passes, a `KP` ctx
     is blocked (proves rows unioned into one AllowOnly rule, not per-row).
- **API round-trip (handler-level).** New
  `crates/waf-api/tests/handler_geo_rules.rs` (follow `handler_hosts_crud.rs` /
  `tests/common` harness): POST `/api/geoip/rules` with a block rule, GET to
  confirm it persisted, then assert the file at `geo_api::rules_path` contains a
  row the Phase-1 loader parses to a Block rule (parse it with `parse_geo_rules`
  and assert the mapped `iso_codes`). This locks the API-writes ↔ engine-reads
  contract (the path-agreement risk from Phase 2) without depending on watcher
  timing. Also POST `/api/geoip/lookup` and assert the stub envelope when no xdb.

## Related Code Files

- Create: `crates/waf-engine/tests/geo_rules_enforcement.rs`
- Create: `crates/waf-api/tests/handler_geo_rules.rs`
- Reference: `crates/waf-engine/tests/engine_lifecycle.rs` (engine fixture,
  `geo_check()` at line 45), `checks/geo.rs` tests (`make_ctx`),
  `crates/waf-api/tests/handler_hosts_crud.rs` + `tests/common` (API harness),
  `crates/waf-api/tests/geoip*`/`handler_*` for the state builder pattern

## Implementation Steps

1. Write `geo_rules_enforcement.rs` (block, delete-clears, allow-only cases).
2. Write `handler_geo_rules.rs` (POST→GET→file-parse contract + lookup stub).
3. `cargo test -p waf-engine geo`, `cargo test -p waf-api geo`.
4. `cargo test --workspace` (touched crates at minimum).
5. `cargo clippy --workspace --all-targets` → zero warnings on changed code.
6. `cargo fmt --all` → `cargo fmt --all --check` clean.

## Success Criteria

- [ ] Engine test: block rule loaded via file → `KP` blocked, `US` allowed.
- [ ] Engine test: removing the rule + reload → `KP` no longer blocked.
- [ ] Engine test: two allow rows → non-listed country blocked, listed allowed
      (single unioned AllowOnly rule).
- [ ] API test: POST rule → file at `rules_path` parses to the expected Block
      rule via `parse_geo_rules` (API↔engine path/contract agreement).
- [ ] API test: `lookup_ip` returns the stub envelope with no xdb, `success:true`.
- [ ] `cargo test` (waf-engine, waf-api), `clippy`, `fmt --check` all green.

## Risk Assessment

- **xdb absence blocks a real-country lookup assertion (handled).** Assert the
  stub/fallback path in CI; the mapping (`GeoIpInfo`→JSON) is unit-tested pure.
- **API harness setup cost (Med).** Reuse `tests/common` and an existing
  `handler_*` test as the template for building `AppState`/router; do not hand-roll.
- **Repo rule.** No plan/issue/FR identifiers in test names or code comments —
  name tests by behavior (e.g. `block_rule_from_file_is_enforced`).
</content>
