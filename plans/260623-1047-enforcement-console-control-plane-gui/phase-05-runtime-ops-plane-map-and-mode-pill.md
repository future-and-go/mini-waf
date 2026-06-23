---
phase: 5
title: "Runtime Ops, Plane Map and Mode Pill"
status: pending
priority: P2
dependencies: [3, 4]
effort: "M"
---

# Phase 5: Runtime Ops, Plane Map and Mode Pill

## Overview

Three smaller surfaces that share the Phase 4 capabilities query: Runtime
Operations (S3, reset/flush), Governance Plane Map (S6, read-only matrix), and the
Global Mode Pill (S4, header widget). Grouped because each is small and reuses the
established hook + `ModeTag`.

## Requirements

### S3 — Runtime Operations (`Card title="Runtime operations"`)
- **Reset runtime state**: danger button (`ReloadOutlined`) → `Modal.confirm`
  (clears risk/rate-limit/cache/challenge/session/temp state; audit log preserved)
  → `POST /api/enforcement/reset-state`. On success: `message.success` + render
  `audit_log_preserved: true` and `ts_ms` (dayjs-formatted). Disable while pending;
  await (no polling).
- **Flush cache**: button (`ClearOutlined`) → `POST /api/enforcement/flush-cache`.
  Per plan Open Question #1: if the response carries `supported:false`, show
  `Alert type="info"` "Caching not implemented — nothing to flush"; otherwise show
  success. Treat a missing `supported` field as supported (current backend shape).

### S6 — Governance Plane Map (read-only matrix)
- antd `Table`, columns: Capability · Config plane · Admin plane · Control plane.
- Config/Admin columns are **static metadata** hard-coded in
  `src/utils/governance-map.ts` (derived from the spec's boundary table); Control
  column is always ✓ (all 17 toggleable). Cells show ✓ + a deep-link (`useGo`)
  where a plane offers a page (e.g. access_control Admin → `/ip-rules`).
- Footer note (verbatim intent): "A detector disabled in config produces no
  verdict — toggling its mode here has no effect. Enabling/tuning a capability is
  always a Config or Admin operation, never a Control one."

### S4 — Global Mode Pill (`<ModePill>` in header)
- Mount in `src/layouts/app-layout.tsx` header inside the `<Space size="middle">`,
  left of the language `Select` (~app-layout.tsx:197–199).
- Reads `active.default_mode` from the **same** `useCustom` queryKey
  (`["enforcement-capabilities"]`) as the console — no double fetch.
- ENFORCE → solid success `Tag` + shield icon; LOG_ONLY → amber `Tag` + eye icon.
- If overrides exist, append `Badge count={n}`; click pill → navigate `/enforcement`.
- No mode-flip from the header (avoid accidental global change).
- `aria-label` describing current mode.

## Architecture

`governance-map.ts` exports a typed array consumed by both the plane map (S6) and
the per-feature plane badges referenced in Phase 4 — so Phase 4 imports this
module. To avoid a circular dependency, the static map is a leaf util with no UI
imports. The pill and runtime-ops use `useCustomMutation` (reset/flush) and the
shared caps query (pill).

Decompose: `plane-map.tsx` (S6 table + footer), `mode-pill.tsx` (S4 header
widget). Runtime Operations is small enough to live in `enforcement/index.tsx`
as a `Card`, or extract `runtime-operations.tsx` if `index.tsx` nears 200 LOC.

## Related Code Files

- Create: `web/admin-panel/src/utils/governance-map.ts` — static Config/Admin/
  Control mapping per capability + optional deep-link path per plane cell.
- Create: `web/admin-panel/src/pages/enforcement/plane-map.tsx` — S6 matrix.
- Create: `web/admin-panel/src/components/mode-pill.tsx` — S4 header pill.
- Modify: `web/admin-panel/src/pages/enforcement/index.tsx` — mount plane map +
  runtime-operations card.
- Modify: `web/admin-panel/src/layouts/app-layout.tsx` — mount `<ModePill>` in the
  header `<Space>` left of the language selector (~lines 197–199).
- Reference: `mode-tag.tsx`, `enforcement-provider.ts`, shared caps queryKey.
- i18n: `enforcement.resetConfirm`, `enforcement.flushNotSupported`,
  `enforcement.planeMap`, plane/footer labels, pill aria text in `en/vi/zh`.

## Implementation Steps

1. Author `governance-map.ts` from the spec boundary table (all 17 capabilities;
   Config/Admin ✓ + deep-link where a page exists; Control always ✓).
2. Build `plane-map.tsx` (Table + footer note); wire deep-links via `useGo`.
3. Add the per-feature plane badges to `capability-catalog.tsx` (deferred from
   Phase 4), importing this map; badges link out via `useGo`.
4. Add Runtime Operations card (reset/flush) with confirm + pending + result line;
   implement the flush not-supported branch per Open Question #1.
5. Build `mode-pill.tsx` using the shared caps queryKey; mount in `app-layout.tsx`.
6. `tsc --noEmit`; manual check: pill reflects live mode + override count, links to
   console; reset/flush behave; matrix deep-links navigate.

## Success Criteria

- [ ] Reset shows `audit_log_preserved: true` + formatted `ts_ms`; button disabled
      while pending.
- [ ] Flush handles not-supported gracefully (info alert) and success otherwise.
- [ ] Plane map renders all 17 capabilities; footer note present; deep-links work.
- [ ] Mode pill reflects live default mode + override count; click → `/enforcement`;
      no mode-flip control in header; has `aria-label`.
- [ ] Pill and console share one network fetch (verify single request in devtools).
- [ ] `tsc --noEmit` clean; strings i18n in all three locales.

## Risk Assessment

- **Double fetch** if the pill uses a different queryKey. Mitigated by reusing
  `["enforcement-capabilities"]` and verifying one request in devtools.
- **Stale deep-links** in the governance map (pages renamed). Mitigated by
  sourcing paths from real nav-items routes and a Phase 7 link check.
- **Circular import** Phase4 ↔ governance-map. Mitigated by keeping the map a
  UI-free leaf util.

Rollback: pill mount is one line in app-layout; other files are additive.
