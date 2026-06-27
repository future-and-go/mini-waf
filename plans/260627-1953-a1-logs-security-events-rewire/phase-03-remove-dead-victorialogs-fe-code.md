---
phase: 3
title: "Remove dead VictoriaLogs FE code"
status: pending
priority: P2
effort: "1h"
dependencies: [1, 2]
---

# Phase 3: Remove dead VictoriaLogs FE code

## Overview
Delete the now-unused VictoriaLogs data provider and its registration, remove
the "VictoriaLogs disabled" alert, and clean the orphan imports this change
creates. VictoriaLogs is permanently gone (decision 0010, E12 completed).

## Requirements
- Functional: app builds and the Logs page loads with no console 404s.
- Non-functional: surgical — clean only the orphans THIS change creates; do not
  refactor adjacent code.

## Architecture
Verified vlogs touchpoints (this session): `App.tsx:13` (import), `App.tsx:74`
(resource meta), `App.tsx:124` (provider registration); `index.tsx:104`
(`dataProviderName`), `index.tsx:~194` (disabled `Alert`).
- `providers/victoria-logs-data-provider.ts` is dead once Phases 1–2 stop using
  the `vlogs` provider. Delete it.
- Remove the provider registration at `App.tsx:124` (`vlogs: victoriaLogsDataProvider`)
  and the import at `App.tsx:13`.
- **`App.tsx:74`**: the `logs` resource is registered with
  `meta: { dataProviderName: "vlogs" }`. Remove the `meta.dataProviderName` (or
  the whole `meta` if that's all it holds) so the kept `logs` resource resolves
  via the default provider — otherwise it dangles to the deleted provider.
  <!-- Updated: Validation Session 1 - fix App.tsx:74 resource meta -->
- Remove the disabled-state `Alert` block in `pages/logs/index.tsx` (~`:194`)
  AND the disabled-detection heuristic (`index.tsx:142–147`) that gates it.
- Drop now-unused imports in the touched files.

## Related Code Files
- Delete: `web/admin-panel/src/providers/victoria-logs-data-provider.ts`
- Modify: `web/admin-panel/src/App.tsx` (remove `vlogs` provider registration)
- Modify: `web/admin-panel/src/pages/logs/index.tsx` (remove disabled alert + imports)

## Implementation Steps
1. Remove the `vlogs` entry from the `dataProvider` map (`App.tsx:124`) and the
   provider import (`App.tsx:13`).
2. Remove `meta.dataProviderName: "vlogs"` from the `logs` resource (`App.tsx:74`).
3. Delete `victoria-logs-data-provider.ts`.
4. Remove the "VictoriaLogs disabled" alert (~`index.tsx:194`), its detection
   heuristic (`index.tsx:142–147`), and any now-unused imports.
5. Build and grep for residue.

## Success Criteria
- [ ] `rg "vlogs|victoria" web/admin-panel/src` → no hits.
- [ ] `pnpm build` (in `web/admin-panel`) succeeds.
- [ ] No console 404s on the Logs page.

## Risk Assessment
- Other pages referencing `vlogs` would break — grep confirmed only the Logs
  page uses it. Reversible: restore the file + registration from git.
