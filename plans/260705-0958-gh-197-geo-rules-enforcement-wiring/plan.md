---
title: "GH-197 geo rules: wire API CRUD to GeoCheck enforcement + real IP lookup"
description: "Geo rule CRUD writes configs/geo-rules.yaml that nothing loads; wire an engine-owned load + hot-reload watcher into GeoCheck, and back lookup_ip with GeoIpService."
status: completed
priority: P1
branch: "main-harness"
tags: [bug, area:api, geo, security, gh-197]
blockedBy: []
blocks: [260705-0958-gh-203-geo-allowonly-fail-policy-reload-guard]
created: "2026-07-05"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/197
---

# GH-197 geo rules: wire API CRUD to GeoCheck enforcement + real IP lookup

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/197 (P1 bug, CONFIRMED by
multi-agent review 2026-07-03; all claims re-verified on HEAD `9ee484b`, 2026-07-05).

The geo admin API is a write-only façade — three independent gaps:

1. **CRUD writes a file nothing loads.** `create/patch/delete_geo_rule`
   (`crates/waf-api/src/geo_api.rs:82-143`) persist to `configs/geo-rules.yaml`
   via `write_rules` (`geo_api.rs:46`). `GeoCheck::load_rules`
   (`crates/waf-engine/src/checks/geo.rs:68`) has zero production callers, and
   `geo-rules` appears nowhere in `crates/prx-waf/src/main.rs`. The engine's
   `geo_check` (`engine.rs:92`, constructed empty at `engine.rs:193`) evaluates
   an always-empty `DashMap` at `engine.rs:850`. Admin POSTs "block KP" →
   `success:true`, rule listed in GET — traffic from KP passes.

2. **Schema mismatch.** The API stores flat per-row records
   `{id, iso_code, action, scope, enabled, country_name}` (`geo_api.rs:92-100`);
   the engine's `GeoRule` (`checks/geo.rs:23-31`) is
   `{id: String, name, mode: GeoRuleMode, iso_codes: HashSet, countries: HashSet}`
   keyed per host in `GeoCheck`. The file cannot be handed to the engine as-is;
   a mapping is required.

3. **`lookup_ip` is a hardcoded stub.** `lookup_ip` (`geo_api.rs:147-159`)
   returns `iso_code:"XX"` / "GeoIP database not loaded" and ignores its state
   argument (`_state`), despite a working `GeoIpService` (`geoip.rs`) already
   wired into the engine at startup (`main.rs:1655-1683`, `engine.set_geoip`).

Established repo pattern to follow: engine-owned `start_*_watcher(&self, path)`
(rate-limit `engine.rs:329`, tx-velocity `engine.rs:366`, ddos `engine.rs:396`)
called from `main.rs` `setup()` (~lines 1607-1644), fail-soft on missing/bad
file, backed by a per-subsystem `notify` reloader (`checks/ddos/reload.rs`). The
admin API writes the same file the watcher loads, so PUT/POST hot-reloads with
no extra API→engine call (ddos does exactly this — `main.rs:1613-1616`).

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Shared geo rule schema + engine loader/mapping](./phase-01-shared-geo-rule-schema-engine-loader-mapping.md) | Completed |
| 2 | [Geo rules hot-reload watcher + startup wiring](./phase-02-geo-rules-hot-reload-watcher-startup-wiring.md) | Completed |
| 3 | [Real lookup_ip backed by GeoIpService](./phase-03-real-lookup-ip-backed-by-geoipservice.md) | Completed |
| 4 | [Acceptance tests + quality gates](./phase-04-acceptance-tests-quality-gates.md) | Completed |

## Key Decisions

- **Explicit mapping, API YAML shape unchanged (not serde on `GeoRule`).** The
  API file is a flat per-row list the admin UI reads/writes; `GeoRule` uses
  `HashSet` + a `GeoRuleMode` enum grouped per host, which is not a 1:1 serde
  target for that shape. Adding `serde` to `GeoRule` would force changing the
  API/file contract (and the FE that consumes it) — out of scope. Instead add a
  small engine-side loader that deserializes the API's own row shape and maps it
  to `Vec<GeoRule>`. Keeps the public API/file contract stable and the mapping
  in one owned place.
- **Aggregate rows into one Block + one AllowOnly rule per host.** Block rows
  union their `iso_code`s into a single `GeoRuleMode::Block` `GeoRule`; allow rows
  union into a single `GeoRuleMode::AllowOnly` `GeoRule`. Rationale: the engine
  evaluates each rule independently, so N separate `AllowOnly` rules would make
  every visitor fail all-but-one (allow-US rule blocks a CA visitor). One unioned
  AllowOnly rule per host is the only correct mapping and pre-empts the GH-203
  fail-policy concern. `enabled:false` rows are skipped at map time.
- **Engine owns load + hot-reload; API does not push.** Add
  `WafEngine::load_geo_rules(path)` (sync initial load, reusable by tests) and
  `WafEngine::start_geo_watcher(path)` (initial load + `notify` reloader), held
  in a new `geo_reloader: OnceLock<GeoReloader>` field mirroring `ddos_reloader`
  (`engine.rs:140`). Wire in `main.rs setup()` after the tx-velocity block,
  resolving `configs/geo-rules.yaml` with the same parent/parent logic the ddos
  path uses (`main.rs:1617-1622`) so it matches `geo_api::rules_path`
  (`geo_api.rs:20-31`). API CRUD relies on the watcher — no new API→engine call.
- **Loader replaces the full rule set and clears absent hosts.** Each load
  parses the whole file, groups per host code (`scope:"global"` → `"*"`, else the
  scope value), and calls `geo_check.load_rules(host, rules)`; hosts present
  before but absent now get `clear_rules`. Full-snapshot replace matches every
  other `*_watcher` (store the parsed snapshot, not a diff).
- **`lookup_ip` reads through the engine handle.** Add
  `WafEngine::geoip_lookup(&self, ip) -> Option<GeoIpInfo>`
  (`self.geoip.get().map(|g| g.lookup(ip))`; the `OnceLock<Arc<GeoIpService>>`
  at `engine.rs:107` currently has no public accessor). `lookup_ip` parses the
  IP, calls it via `state.engine`, and maps `GeoIpInfo` → response; `None`
  (service disabled) or empty info (private IP / xdb miss) falls back to the
  existing "not loaded" style stub. No behavior change when GeoIP is off.

## Cross-Plan Dependencies

- **Blocks GH-203** (`260705-0958-gh-203-geo-allowonly-fail-policy-reload-guard`):
  issue 203 fixes AllowOnly fail-policy + reload-guard behavior and explicitly
  notes ordering matters because geo rules are never loaded today. This plan
  establishes the load path; land it first. The one-unioned-AllowOnly-rule
  mapping here already removes the multi-allow footgun, but 203 owns the deeper
  fail-open/empty-geo policy and the reload race guard.
- **No overlap with GH-196** (`260705-0953-gh-196-risk-admin-api-engine-wiring`):
  that plan touches risk store/scorer + `risk_api.rs`; this touches `geo_*` and a
  new geo config module. Both add a `main.rs setup()` block and an engine
  `OnceLock` reloader field — distinct, adjacent regions; no shared symbols.

## Acceptance Criteria (from issue)

- [x] One rule schema shared between API and engine (explicit mapping; file shape
  unchanged) — Phase 1.
- [x] Save path loads rules into `engine.geo_check()` at startup and on
  hot-reload — Phases 1–2.
- [x] `lookup_ip` backed by `GeoIpService` — Phase 3.
- [x] Integration test: create block rule via API → request from that country is
  blocked — Phase 4.

## Validation

- `cargo test -p waf-engine geo` and `cargo test -p waf-api geo` green.
- Integration test: write/POST a block-KP rule → engine loads → a `KP` request
  is blocked by `Phase::GeoIp`; an allow-only rule blocks a non-listed country.
- `lookup_ip` test: with no xdb (default CI), returns the stub; mapping asserted
  against a populated `GeoIpInfo`.
- `cargo clippy --workspace --all-targets` clean; `cargo fmt --check`.
</content>
</invoke>
