# 2026-07-05 — GH-203: geo AllowOnly fail policy + reload guard

## What

Two fail-open geo defects fixed on branch `fix/gh-203-geo-allowonly-fail-policy`
(stacked on `fix/gh-202-riskbump-actor-keyed-submit`):

1. **Reload could swap a working searcher for `None`.**
   `GeoIpService::reload` now decides per address family via a
   `FamilyReload<T>` seam: new load succeeds → swap; fails with a working
   searcher present → keep the old one and return `Err` naming the family;
   fails with an empty slot → stay empty, no error (first-time/degraded
   unchanged). The only production caller (`geoip_updater.rs`) already
   surfaces `Err` via `warn!` — no caller change.

2. **AllowOnly failed open whenever geo data was unavailable.**
   `GeoRule` gained `fail_closed: bool` (default `false` — behavior
   unchanged unless opted in). `GeoCheck::check` routes absent/empty geo to
   `eval_fail_closed`, which blocks only when a fail-closed AllowOnly rule
   applies (host-then-global, same precedence as `eval_rules`). Block rules
   never fail closed. The knob rides the API row (`fail_closed` on
   `action:"allow"` rows, persisted by create/patch handlers) and is OR-ed
   into the host's single unioned AllowOnly rule by `parse_geo_rules`
   (most-restrictive wins).

## Verified

- `geoip.rs`: `family_reload` decision matrix unit tests + service-level
  degraded-reload tests (`Ok(false)`, no error, still unavailable).
- `geo.rs`: fail-closed blocks on `None` and empty geo; fail-open regression
  guard; data-present matching unchanged; block-mode never fails closed.
- `geo_config.rs`: OR aggregation, default-false, block-row `fail_closed`
  ignored.
- Acceptance appended to `tests/geo_rules_enforcement.rs` (CI, docker-gated
  locally): allow row `fail_closed:true` → empty/absent geo blocked, listed
  country passes; without the flag → fail-open unchanged.
- API round-trip appended to `waf-api/tests/handler_geo_rules.rs` (CI):
  create with `fail_closed:true` → GET/loader show it; PATCH toggles it.
- waf-engine lib: 1438 passed + known 6 docker-gated `engine::tests`
  failures. Workspace clippy (and waf-engine with `redis-store`) clean; fmt
  clean.

## Gotchas

- No valid xdb fixture exists in the repo, so the preserve-working-searcher
  path cannot be exercised end-to-end locally; the `FamilyReload` seam
  covers the decision matrix instead (the plan's documented fallback).
- With GeoIP fully disabled (`ctx.geo = None`), a fail-closed AllowOnly rule
  blocks matching hosts — intentional, opt-in; internal ranges are exempted
  upstream by the FR-008 IP allowlist which short-circuits before geo.
- `fail_closed` is stored on every API row but only read for allow rows.
