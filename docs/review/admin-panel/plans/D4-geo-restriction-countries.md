# D4 — Geo Restriction: full country list + accurate "Top Blocked" label

**G.1 rows:** 18, 19 · **Req IDs:** FR-041 (Geographic Restriction) ·
**Lane:** tiny (country list + label) → normal (server-side 24h/blocked filter)

> Companion: spec §D4. Follows [`ARCHITECTURE.md`](../../../ARCHITECTURE.md)
> and [`CONTEXT_RULES.md`](../../../CONTEXT_RULES.md).

---

## 1. Codebase audit (current state)

**Frontend** (`web/admin-panel/src/pages/geo-restriction/index.tsx`):
- `COUNTRY_MAP` is a hardcoded ~30-entry `{ iso → { name, flag } }` (lines
  54-85), used for labels, the lookup flag, and the add-country `Select`
  (lines 448-451). It's incomplete (only ~31 of ~250 ISO codes).
- Live endpoints: `GET/POST /api/geoip/rules`, `PATCH`/`DELETE
  /api/geoip/rules/{id}`, `POST /api/geoip/lookup`, `GET /api/stats/geo`
  (`GeoStat { iso_code, country_name?, count }`).
- The "Top Blocked Countries (24h)" card (lines 386-410) hardcodes "24h" in the
  label, but `GET /api/stats/geo` takes **no `hours`/`action` query param** —
  the window is whatever the backend aggregate returns, and it's not filtered to
  blocked-only.

**Backend reality:**
- `stats_geo` (`stats.rs:193-204`) takes **no query struct**; returns
  `top_countries/top_cities/top_isps/country_distribution` from DB aggregates.
- No `GET /api/geoip/countries` endpoint. `lookup_ip` is a stub returning
  `iso_code:"XX"` (GeoIP DB not loaded).

## 2. Gap

1. Country picker is missing most countries. 2. The "(24h) Top Blocked" label
overstates what `/api/stats/geo` actually returns (not time-bounded, not
blocked-filtered).

## 3. Assumptions (explicit)

- A-1: A complete ISO-3166-1 alpha-2 list with names is acceptable bundled in the
  FE (static, ~250 entries) — no backend needed for the picker. Flags can be
  derived from ISO code (regional-indicator emoji) instead of a hardcoded map.
- A-2: For the label, the minimal honest fix is to **relabel** to match what
  `/api/stats/geo` returns (e.g. "Top Countries"); adding a real 24h/blocked
  filter is a separate normal-lane backend change.
- A-3: GeoIP DB loading (so `lookup_ip` returns real data) is a separate concern
  (FR-041 infra) — out of scope here.

## 4. Scope

**In scope:** replace `COUNTRY_MAP` with a full ISO list (bundled) + emoji-flag
derivation; relabel the "Top Blocked (24h)" card to be accurate; optionally add
server-side `hours`/`action` filters to `/api/stats/geo`.

**Out of scope:** loading the MaxMind GeoIP DB (`lookup_ip` stub); VPN/geo-bypass
detection; a `GET /api/geoip/countries` endpoint (FE static list suffices).

## 5. Phased plan (independently testable & reversible)

### Phase 1 — Full country list (FE-only, tiny)
- Add a static `iso-countries.ts` (full ISO-3166-1 alpha-2 + names); derive flag
  emoji from the code; replace `COUNTRY_MAP` usages (Select, labels, lookup flag).
- **Success:** the add-country Select lists all countries; existing rules with
  any ISO code render a correct name+flag; `rg COUNTRY_MAP` → no remaining usage.
- **Reversible:** one-file revert + keep the old map.

### Phase 2 — Accurate "Top Blocked" label (FE-only, tiny)
- Relabel the card to reflect `/api/stats/geo` semantics (drop "24h"/"Blocked"
  unless filtered). Keep the data source unchanged.
- **Success:** the card title matches the data (no misleading time/blocked
  qualifier); reviewer confirms against `stats_geo` output.
- **Reversible:** i18n/label-only revert.

### Phase 3 (optional, normal) — real 24h/blocked filter
- Add an `OverviewQuery`-style `{ hours?, action? }` to `stats_geo`
  (mirror `stats_endpoints`); restore the "24h Top Blocked" label backed by the
  filter.
- **Success:** `GET /api/stats/geo?hours=24&action=block` returns blocked-only
  last-24h aggregates; integration test; the label is now truthful.
- **Reversible:** the query params are optional/additive; default keeps current
  behavior.

## 6. Edge cases & failure modes

- Unknown/`XX` ISO code (lookup stub) → render "Unknown" gracefully.
- Non-alpha-2 codes from old rules → fall back to showing the raw code.
- Empty `/api/stats/geo` → empty card, not error.
- Emoji-flag rendering on platforms without flag glyphs → still show the code/name.

## 7. Security

- Read-only display + existing rule CRUD (already behind `require_auth`). No new
  mutation in Phases 1–2.
- Phase 3 query params parsed at the boundary (parse-first); `action` validated
  against the known decision classes.

## 8. Observability

- None new for Phases 1–2. Phase 3 adds a canonical log line and reuses existing
  stats query logging.

## 9. Production-readiness gaps

- `lookup_ip` is a stub (GeoIP DB not loaded) — FR-041 enforcement accuracy
  depends on loading MaxMind; flag separately.
- Without Phase 3, the geo "top blocked" view is approximate; document it.

## 10. Harness intake

- **Lane:** tiny (Phases 1–2). Phase 3 is normal (public contract change to
  `/api/stats/geo`) → short story.
- **Validation:** FE manual (full picker, accurate label); Phase 3 integration
  test. Record intake row / `harness-cli story update`.
