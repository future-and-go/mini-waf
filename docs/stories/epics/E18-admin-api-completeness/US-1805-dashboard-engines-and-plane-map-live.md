# US-1805 Dashboard Detection Engines + Enforcement Plane Map from live state

## Status

implemented

## Lane

tiny (FE display correctness)

Plans: `docs/review/admin-panel/plans/D1-dashboard-detection-engines.md`,
`docs/review/admin-panel/plans/D2-enforcement-plane-map.md`.
Gap spec §D1 (G.1 row 15), §D2 (row 16). Req IDs: FR-030, FR-031, E10, E14.

## Product Contract

Two dashboards must stop presenting hardcoded all-green state as if it were
live: the Dashboard "Detection Engines" panel and the Enforcement "Plane Map"
control-plane column.

## Acceptance Criteria

- **D1**: each Detection-Engine indicator is derived from already-fetched live
  data (`/api/rules/registry` + `/api/panel-config`); engines with no live
  signal render a neutral "static" tag instead of green.
- **D2**: the Plane Map control-plane cell is driven by
  `/api/enforcement/capabilities` (via the existing `useEnforcementCapabilities`
  hook); features absent from the capabilities response render a neutral
  "reference" marker — no row is unconditionally green.
- Both degrade gracefully on load/error (neutral, never green). FE-only; no new
  backend; no i18n-file edits (inline `defaultValue`).

## Design Notes

- FE-only, implemented in `web/admin-panel/src/pages/dashboard/index.tsx` (D1)
  and `web/admin-panel/src/pages/enforcement/plane-map.tsx` (D2). Reuses
  endpoints/hooks the pages (or sibling pages) already consume; no new requests.

## Validation

| Layer | Expected proof |
| --- | --- |
| Build | `tsc --noEmit` + `vite build` clean (compiled into the prx-waf image). |
| E2E | live Docker: `/api/rules/registry`, `/api/panel-config`,
  `/api/enforcement/capabilities` all return 200 (the panels' data sources);
  visual indicators reflect config rather than unconditional green. |

## Evidence

Verified 2026-06-29: FE typechecks + Docker `vite build` succeeded with both
files modified; the three source endpoints return 200 live. Visual correctness
is a render-time change (no API surface added).
