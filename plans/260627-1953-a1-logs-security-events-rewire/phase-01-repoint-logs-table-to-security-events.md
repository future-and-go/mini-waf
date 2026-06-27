---
phase: 1
title: "Repoint logs table to security-events"
status: pending
priority: P1
effort: "3h"
dependencies: []
---

# Phase 1: Repoint logs table to security-events

## Overview
Replace the `vlogs`/VictoriaLogs data source in the Logs page table with the
live default-data-provider `/api/security-events` feed, via a single typed
boundary mapper. Closes the primary 404.

## Requirements
- Functional: Logs table renders real rows from `/api/security-events` with
  pagination; no calls to `/api/v1/logs/*`.
- Non-functional: parse-first — one typed `SecurityEvent → LogRow` mapper, no
  scattered `any`.

## Architecture
- `pages/logs/index.tsx` currently uses
  `useList({ dataProviderName: "vlogs", ... })` (verified `index.tsx:104`).
  Swap to the default provider with an explicit resource override:
  `useList({ resource: "security-events", pagination, filters, sorters })`.
  The page stays mounted at the `/logs` route; the registered `logs` resource
  (`App.tsx:74`) keeps its route/nav but loses its `vlogs` meta in Phase 3.
  <!-- Updated: Validation Session 1 - resource override + /logs route retained -->
- There is no `/api/logs` backend endpoint, so the `useList` MUST override
  `resource: "security-events"` (cannot rely on the resource name → URL default).
- Mirror the working pattern in `pages/security-events/index.tsx` and
  `pages/tx-velocity/index.tsx`.
- Add a boundary mapper `SecurityEvent → LogRow` (the table's existing row type
  in `LogsTable.tsx:25-44`). Field map:
  - `created_at` → `_time` (RFC3339; render in browser locale).
  - `client_ip`, `rule_name`, `rule_id`, `method`, `path` → direct.
  - `host_code` → `host`.
  - `detail` → `detail` (nullable → safe default).
  - `event_type` → derive from `action` (or drop the column; reuse
    `deriveCategory`/action mapping already in `types/api.ts`).
  - `tier` → drop or map from available field (no direct equivalent).
- Envelope: default provider already unwraps `{ success, data, total }`.

## Related Code Files
- Modify: `web/admin-panel/src/pages/logs/index.tsx`
- Modify: `web/admin-panel/src/pages/logs/LogsTable.tsx` (row type / mapper call site)
- Create (or colocate in index): `SecurityEvent → LogRow` mapper
- Read for pattern: `web/admin-panel/src/pages/security-events/index.tsx`,
  `web/admin-panel/src/pages/tx-velocity/index.tsx`,
  `web/admin-panel/src/types/api.ts` (`SecurityEvent`, `deriveCategory`)

## Implementation Steps
1. Add the typed `SecurityEvent → LogRow` mapper (single function, exported).
2. Replace the `vlogs` `useList` call with the default-provider call using
   `resource: "security-events"`, wiring `page`/`page_size` pagination.
3. Pipe mapped rows into `LogsTable`; supply safe defaults for null fields.
4. Remove the `event_type`/`tier` columns that have no source, OR derive
   `event_type` from `action` — pick one and keep the table coherent.

## Success Criteria
- [ ] Logs table renders real rows; Network tab shows `GET /api/security-events?...` 200.
- [ ] **Zero** requests to any `/api/v1/logs/*` from the Logs page.
- [ ] `rg "/api/v1/logs" web/admin-panel/dist` → no hits after build.
- [ ] No `any` introduced in the mapper.

## Risk Assessment
- Field gaps (`tier`, `event_type`) → decide derive-vs-drop in step 4; don't
  fabricate values. Reversible: revert the single page file; provider still
  registered (removed in Phase 3).
