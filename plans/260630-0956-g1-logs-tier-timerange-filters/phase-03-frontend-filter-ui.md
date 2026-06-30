---
phase: 3
title: "Restore tier + time-range filter UI"
status: done
priority: P2
dependencies: [2]
---

# Phase 3: Restore tier + time-range filter UI

## Overview
Re-add the tier multi-select and the time-range picker (with 1h/6h/24h/7d presets) to
the Security Logs filter panel, mapping them to the new backend query params. Surface
the `tier` column in the table (the `LogRow.tier` field already exists but is unused).

## Requirements
- Functional: user can select one or more tiers and an absolute time range (or a preset);
  results update via server pagination. Default load = **last 1 hour** range (D1,
  validation session 1).
- Non-functional: no new data-provider code — reuse the existing `field → param`
  flattening; match current `LogsFilters` styling.

## Architecture
`LogsFilters.tsx` owns filter state and `filtersToCrud()`, which produces `CrudFilter[]`
that `data-provider.ts` flattens into query params (`params[field] = value`). So mapping
is purely: choose `field` names that match the backend params from Phase 2.
- tier: `{ field: "tier", operator: "eq", value: tiers.join(",") }` (D2)
- range: `{ field: "created_at_from", … }` and `{ field: "created_at_to", … }`
  using `dayjs(...).toISOString()` (RFC3339 with offset).
Presets are buttons computing `[now - delta, now]`. The pre-rewire implementation
(recoverable from git commit `878998e`, `LogsFilters.tsx`) is the visual reference for
the range presets + tier multi-select — reuse its layout, not its VictoriaLogs mapping.

## Related Code Files
- Modify:
  - `web/admin-panel/src/types/api.ts` **(finding 4 — required for `tsc`)** — add
    `tier?: string | null;` to the `SecurityEvent` interface (~:163-184). Without this,
    `toLogRow` reading `e.tier` fails `tsc --noEmit`.
  - `web/admin-panel/src/pages/logs/LogsFilters.tsx` — extend `LogsFilterState` with
    `tiers: string[]` and `range?: [string, string]`; add a `Select mode="multiple"`
    (options `Critical|High|Medium|CatchAll`, exact PascalCase per D3), a
    `DatePicker.RangePicker showTime`, and preset buttons; extend `filtersToCrud()`.
  - `web/admin-panel/src/pages/logs/index.tsx` — map `tier` into `toLogRow` (~:30) so
    the column has data; <!-- Updated: Validation Session 1 - default range = last 1h -->
    set the default filter range to **last 1 hour** on load (D1), matching the original
    pre-rewire default. Tier default stays empty.
  - `web/admin-panel/src/pages/logs/LogsColumns.tsx` — show the `tier` column (colored
    tag optional, mirroring the `event_type` tag style at ~:66-70).
  - `web/admin-panel/src/pages/logs/LogsColumnsPicker.tsx` **(fold-in, finding 10)** —
    register the new `tier` column in the picker's known-columns set, else it may render
    hidden or desync the picker. Verify the picker governs the column set before editing.

## Implementation Steps
0. Add `tier?: string | null` to the `SecurityEvent` type in `types/api.ts` (finding 4).
1. Extend `LogsFilterState` + the panel UI with tier multi-select and range picker +
   presets.
2. Extend `filtersToCrud()` to emit `tier` (comma-joined), `created_at_from`,
   `created_at_to`. **Omit `tier` entirely when `tiers.length === 0`** (finding 9 — do
   not emit `tier=""`, which would zero out results). Emit timestamps via
   `dayjs(...).toISOString()` → `Z`-suffixed RFC3339 only (finding 13 — never a `+00:00`
   offset; the `+` URL-decodes to a space and 400s the request).
3. Map `e.tier` in `toLogRow`; add the tier column in `LogsColumns.tsx` and register it
   in `LogsColumnsPicker.tsx`.
4. Confirm the data provider forwards the new fields unchanged (verified: `data-provider.ts`
   flattens arbitrary `field`→param with no operator special-casing; no provider edit).
   Note (fold-in, finding 14): the logs page refreshes via REST polling
   (`refetchInterval`), not the WS live-tail, so WS broadcast divergence does not affect
   the tier column here.

## Success Criteria
- [ ] Selecting tier(s) and/or a range issues a request with the matching params and the
      table updates; pager `total` reflects the filtered set.
- [ ] Presets populate the range picker and apply correctly.
- [ ] `tier` column renders values for new events AND is toggleable in the columns picker.
- [ ] Clearing the tier multiselect removes the `tier` param entirely (results un-filtered,
      not empty).
- [ ] `tsc --noEmit` (with `tier` on the `SecurityEvent` type) + `vite build` green; no
      dead VictoriaLogs imports reintroduced.

## Risk Assessment
- **Tier string mismatch:** FE options must be exact PascalCase (`CatchAll`, not
  `catch_all`) to match stored values (D3). Mitigation: hard-code from the Tier enum;
  test one query end-to-end.
- **Timestamp format:** send `toISOString()` (RFC3339, `Z`) so the backend parses to
  `DateTime<Utc>`. Mitigation: verified against Phase 2 tests.
- **Behavior change:** if D1 is flipped to "last 1h default", the page would show fewer
  rows on load than today — keep default empty unless the team opts in.
