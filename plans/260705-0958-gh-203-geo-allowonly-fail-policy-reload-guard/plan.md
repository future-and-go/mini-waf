---
title: "GH-203 geo: AllowOnly fail policy + keep-old-searcher reload guard"
description: "AllowOnly fails open on missing/empty geo data and reload can swap a working xdb for None; add a keep-old-on-failure reload guard and an opt-in fail-closed policy for AllowOnly."
status: completed
priority: P2
effort: 5h
branch: "main-harness"
tags: [bug, area:engine, geo, security, gh-203]
blockedBy: [260705-0958-gh-197-geo-rules-enforcement-wiring]
blocks: []
created: "2026-07-05"
createdBy: "ck:plan"
source: skill
issue: https://github.com/future-and-go/mini-waf/issues/203
---

# GH-203 geo: AllowOnly fail policy + keep-old-searcher reload guard

## Overview

Issue: https://github.com/future-and-go/mini-waf/issues/203 (P2 bug,
`risk:security`; found by multi-agent review 2026-07-03, verdict CONFIRMED. All
claims re-verified on HEAD `9ee484b`, 2026-07-05).

Two independent fail-open defects in geo enforcement:

1. **AllowOnly fails open whenever geo data is unavailable.**
   `GeoCheck::check` (`crates/waf-engine/src/checks/geo.rs:165-175`) returns
   `None` when `ctx.geo` is `None` **or** when both `geo.country` and
   `geo.iso_code` are empty (line 171). Even inside `match_rules`, the AllowOnly
   arm only blocks `if !matched && (!geo.country.is_empty() || !geo.iso_code.is_empty())`
   (`geo.rs:124`). So missing xdb, a lookup failure, or a private IP not in the
   database all skip the allowlist — an operator who configured AllowOnly `['US']`
   silently lets every country through. `ctx.geo` is populated at
   `engine.rs:770-771` via `geoip.lookup(ctx.client_ip)`, which returns an empty
   `GeoIpInfo` on missing searcher / lookup error / private IP
   (`geoip.rs:103-105,113-119`). Geo runs at `engine.rs:850` (Phase 17).

2. **Reload can swap a working searcher for `None`.**
   `GeoIpService::reload` (`crates/waf-engine/src/geoip.rs:72-87`)
   unconditionally `store`s the freshly loaded searchers (lines 79-80) and
   returns `Ok(any_loaded)`. If the xdb file is missing/corrupt at reload time,
   `load_searcher` returns `None` (`geoip.rs:131-146`) and a **working** searcher
   is replaced with `None`, silently disabling geo — with only an absent
   `info!`. The only production caller is `geoip_updater.rs:157`
   (`update()`, after a validated atomic download), so live exposure is narrow,
   but the keep-old-on-failure guard is absent and the error is swallowed.

Combined: AllowOnly `['US']` + xdb vanishes at reload → searcher becomes `None`
→ lookup returns empty `GeoIpInfo` → every country allowed.

**Ordering note (why this plan is blockedBy GH-197).** API-created geo rules are
never loaded into `geo_check` today (GH-197), so the AllowOnly fail-open bug is
currently *moot in practice*. GH-197 establishes the load path and maps API rows
into **one unioned AllowOnly rule per host**; this plan adds the fail-policy knob
and the reload guard on top. Phase 1 (reload guard) is independent of GH-197 and
could land alone; Phases 2-3 compose with GH-197's schema and loader.

**Default behavior is unchanged: fail-open.** Fail-closed is strictly opt-in
(default `false`), preserving current behavior — flipping the default silently
would be a user-decision violation.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [Keep-old-on-failure reload guard](./phase-01-keep-old-on-failure-reload-guard.md) | Completed |
| 2 | [AllowOnly fail-closed policy in engine](./phase-02-allowonly-fail-closed-policy-in-engine.md) | Completed |
| 3 | [API knob + GH-197 loader wiring + acceptance](./phase-03-api-knob-gh-197-loader-wiring-acceptance.md) | Completed |

## Key Decisions

- **Reload guard: swap per-family only on success; preserve the old searcher on
  failure and surface an error.** In `reload`, load each family; if the new
  searcher loaded, `store` it; if it did not load **but a searcher is currently
  present**, keep the old one and record that family as failed-but-preserved. If
  it did not load and none was present before, leave `None` (first-time / degraded
  setup — unchanged). Return `Err` when any working searcher was preserved instead
  of replaced (so the caller surfaces it); return `Ok(true)` when at least one
  family swapped in a new searcher; `Ok(false)` when nothing loaded and nothing was
  preserved. Rationale: "swap working→None" is exactly the silent-disable the issue
  targets; guarding *both* the missing-file and corrupt-file cases (both yield
  `None`) is the correct, cause-agnostic fix. The one production caller
  (`geoip_updater.rs:157`) already `if let Err(e) = geoip.reload() { warn! }`, so an
  `Err` return is surfaced without a caller change.

- **Fail policy knob lives on the engine `GeoRule` (`fail_closed: bool`, default
  `false`), sourced through GH-197's file/loader — not a new global geo config.**
  The AllowOnly stance is inherently *per-host allowlist* ("if I can't determine
  the country for this host, deny"), which maps 1:1 onto GH-197's one-AllowOnly-
  rule-per-host model. Reusing GH-197's `configs/geo-rules.yaml` + engine-owned
  watcher + `geo_config.rs` loader (DRY) avoids inventing a second geo config
  surface, a second watcher, and a global switch too coarse to express per-host
  intent. Rejected alternative — a single global `allow_fail_closed` bool in main
  config — is simpler to store but cannot vary per host and needs new plumbing;
  documented as considered.

- **Encode the knob as an optional per-row `fail_closed` field on `action:"allow"`
  rows; the loader ORs it into the host's single AllowOnly `GeoRule`.** The API
  stores flat per-row records (`geo_api.rs:92-100`) and GH-197 unions allow rows
  into one rule, so the only writable unit is the row. Aggregation is
  "most-restrictive wins": if **any** enabled allow row for a host sets
  `fail_closed:true`, that host's AllowOnly rule is fail-closed. Absent field →
  `false` → fail-open (unchanged). Semantic mismatch (a stance set on a country
  row) is documented; a richer per-host policy object is YAGNI-deferred.

- **Fail-closed reaches evaluation by making `check()` policy-aware, not by
  removing the empty-geo short-circuit for everyone.** Today `check()` short-
  circuits on `ctx.geo` `None`/empty (`geo.rs:167-173`) *before* rules are
  consulted. Restructure so that when geo is absent/empty, `check()` still asks
  the host's rules whether any **fail-closed AllowOnly** rule applies; if so →
  `Block` ("geo data unavailable"); otherwise → `None` (fail-open, unchanged).
  Block-mode rules never fire on empty geo (you cannot match a specific blocked
  country with no data — fail-open is correct for Block). This is a control-flow
  change to a hot-path check; it must stay allocation-free on the common
  data-present path.

- **Private-IP / internal-traffic mitigation: the IP whitelist already runs first.**
  Fail-closed will block requests whose IP yields empty geo, including private/
  internal IPs not in the xdb. Verified the IP whitelist (Phase 1) returns `Allow`
  and short-circuits the whole pipeline at `engine.rs:774-781`, *before* geo
  (Phase 17, `engine.rs:850`). So operators enabling fail-closed exempt internal
  ranges via the existing FR-008 IP allowlist; this is the documented mitigation,
  not new code. Also: if the GeoIP service is entirely disabled (`ctx.geo` is
  `None`), a configured fail-closed AllowOnly rule *will* block matching hosts —
  documented as an intentional, opt-in operational consequence (see Open
  Questions).

## Cross-Plan Dependencies

- **BlockedBy GH-197** (`260705-0958-gh-197-geo-rules-enforcement-wiring`, P1):
  GH-197 wires API geo rules into `geo_check` (new `checks/geo_config.rs`
  loader/mapping, engine-owned load + hot-reload watcher, one unioned AllowOnly
  rule per host). The issue explicitly states fix ordering matters — the fail
  policy is moot until rules load. This plan extends GH-197's `GeoRuleRow`,
  `parse_geo_rules` mapping (Phase 3), and the API row handlers; those files are
  **shared but edited sequentially** (blockedBy guarantees no parallel conflict).
  Phases 1-2 touch only `geoip.rs` / `geo.rs` and do not depend on GH-197.

- **Soft note — GH-205** hardens `geoip_updater.rs` download validation
  (checksums / size guards). Different concern; this plan touches
  `geoip_updater.rs` only if needed to surface the new `reload` `Err` (the
  existing `warn!` already does). No overlap expected — coordinate only if both
  touch `update()`.

## Acceptance Criteria (from issue)

- [ ] Reload keeps the previous searcher when the new load fails, and surfaces
  the error (returns `Err`, old searcher still serves lookups) — Phase 1.
- [ ] Fail-open vs fail-closed on empty/missing geo is a config/policy decision
  for AllowOnly, default fail-open (unchanged) — Phases 2-3.
- [ ] Test: reload-with-missing-file keeps old data + surfaces error — Phase 1.
- [ ] Test: AllowOnly + no geo data honors the configured fail mode, both open
  and closed — Phases 2 (unit) + 3 (end-to-end via API).

## Validation

- `cargo test -p waf-engine geoip` — reload guard (Phase 1).
- `cargo test -p waf-engine geo` — AllowOnly fail-open vs fail-closed (Phase 2),
  loader mapping of `fail_closed` (Phase 3).
- `cargo test -p waf-api geo` — API persists/round-trips `fail_closed` (Phase 3).
- Integration/acceptance: create an allow rule with `fail_closed:true` via API →
  a request with empty/absent geo for that host is blocked by `Phase::GeoIp`;
  with `fail_closed:false` the same request passes (Phase 3).
- `cargo clippy --workspace --all-targets` clean; `cargo fmt --check`.
</content>
</invoke>
