---
phase: 2
title: "Filters and 24h entries card"
status: pending
priority: P2
effort: "3h"
dependencies: [1]
---

# Phase 2: Filters and 24h entries card

## Overview
Rewire the Logs page filters and the "Entries (24h)" card off the dead
`/api/v1/logs/*` endpoints onto `SecurityEventQuery` fields and a real stats
endpoint. Remove the LogsQL query bar.

## Requirements
- Functional: filter selections change the result set via real query params;
  the 24h card shows a value traceable to a real endpoint (or is removed).
- Non-functional: no fabricated counts; client-side filtering only where the
  query API has no matching field.

## Architecture
- Filters: `LogsFilters.tsx:88` currently calls `GET /api/v1/logs/streams` for
  dropdown options. Map filters to `SecurityEventQuery`
  (`models.rs:323-336`): `action`, `rule_id_prefix`, `rule_name`, `host_code`,
  `client_ip`, `path`, `country`, `iso_code`. Drop `/streams`; populate dropdown
  options from a static enum (e.g. `action` values) or client-side distinct.
- Query bar: `LogsQueryBar.tsx` is a LogsQL bar — security-events uses
  structured filters, not LogsQL. **Decision: remove it** — the structured
  filters in `LogsFilters` cover the use case; deleting avoids dead complexity.
  <!-- Updated: Validation Session 1 - remove LogsQueryBar (not convert) -->
- 24h card: `index.tsx:42` calls `GET /api/v1/logs/stats`. **Decision: keep the
  card, repoint to `GET /api/stats/overview?hours=24`** — verified live
  (`server.rs:200`, `stats_overview` accepts `hours: Option<i64>` at
  `stats.rs:53–59`). Extract the count field from the overview payload; do
  **not** fabricate a number. Also delete the `/api/v1/logs/stats` fetch helper
  and its disabled-state heuristic (`index.tsx:35–55`).
  <!-- Updated: Validation Session 1 - keep card, wire /api/stats/overview -->

## Related Code Files
- Modify: `web/admin-panel/src/pages/logs/LogsFilters.tsx`
- Delete: `web/admin-panel/src/pages/logs/LogsQueryBar.tsx`
- Modify: `web/admin-panel/src/pages/logs/index.tsx` (24h card data source)
- Read for pattern: `web/admin-panel/src/pages/security-events/index.tsx` filters

## Implementation Steps
1. Map each Logs filter to a `SecurityEventQuery` field; pass through the
   default provider `filters`.
2. Replace `/api/v1/logs/streams` dropdown source with static enum / client-side
   distinct values.
3. Delete `LogsQueryBar` and its usage (LogsQL has no security-events equivalent).
4. Point the 24h card at `GET /api/stats/overview?hours=24` (keep the card).

## Success Criteria
- [ ] Selecting a filter changes the result set (verified against a seeded event).
- [ ] 24h card shows a value traceable to `/api/stats/overview` OR is gone.
- [ ] No remaining calls to `/api/v1/logs/stats` or `/api/v1/logs/streams`.

## Cook decisions (Session 1 — discovered during implementation)
`/api/security-events` (`SecurityEventQuery`) supports only: host_code,
client_ip, rule_id, rule_name, path, action, country, iso_code + page/page_size.
It has **no time-range, tier, or free-text param** (confirmed vs the canonical
`pages/security-events/index.tsx`).
- **Remove** the 3 unsupported controls (time-range picker + presets, tier
  multi-select, free-text search) rather than leave dead UI. (user-confirmed)
- Keep Event Type→`action`, Rule Name→`rule_name`, Client IP→`client_ip`; add
  Host Code→`host_code` and Path→`path` (contains) for parity/usefulness.
- 24h card → `useCustom<StatsOverview>("/api/stats/overview", { hours: 24 })`,
  display `total_requests` (same overview the dashboard KPI uses).
- Backend time param: **out of scope** — FE-only this round; track `from_ts`/
  `to_ts` on `SecurityEventQuery` as a separate backend story. (user-confirmed)

## Risk Assessment
- Removing the time-range control is a visible UX change → accepted by user;
  time filtering deferred to a backend story. Reversible: changes isolated to
  `LogsFilters.tsx` / `index.tsx`.
