# US-1206 Logs page rewire onto /api/security-events

## Status

in-progress

## Lane

normal

## Product Contract

The admin-panel "Security Logs" page must show the live WAF request/attack feed.
After the VictoriaLogs decommission (US-1205, decision 0010), the page called
removed `/api/v1/logs/*` endpoints and 404'd. It must instead read the live
`/api/security-events` feed (the same source the dashboard and security-events
page use).

This story closes the **GUI** view only. True FR-032 (a SIEM-ingestible JSONL
read API over `waf_audit.log`) remains a separate, deferred high-risk follow-up
and is NOT delivered here.

## Relevant Product Docs

- `docs/product/audit-log.md`

## Acceptance Criteria

- Logs page fetches `/api/security-events` via the default data provider; zero
  requests to `/api/v1/logs/*`.
- Server-side pagination (`page`/`page_size`) wired; page resets on filter change.
- Filters map only to supported `SecurityEventQuery` fields (action, rule_name,
  client_ip, host_code, path); unsupported controls (time-range, tier,
  free-text) removed rather than left inert.
- "Entries (24h)" card sourced from `/api/stats/overview?hours=24` (no fabricated
  count).
- Dead VictoriaLogs FE code deleted (provider, query bar, resource meta); build green.

## Design Notes

- Commands: —
- Queries: `GET /api/security-events`, `GET /api/stats/overview?hours=24`
- API: no backend change (FE-only)
- Tables: reads `security_events` (via existing handler)
- Domain rules: `action` filter values match engine-persisted strings
  (`block|allow|challenge|rate_limit|log_only|redirect`), verified at
  `crates/waf-engine/src/engine.rs:978-987`
- UI surfaces: `web/admin-panel/src/pages/logs/*`, `App.tsx`

## Validation

`scripts/bin/harness-cli` is not present in this checkout — proof recorded here
+ in git rather than via `harness-cli story update`.

| Layer | Expected proof |
| --- | --- |
| Unit | N/A — no FE test runner in admin-panel package |
| Integration | N/A |
| E2E | Manual Network-tab check: Logs page issues only `/api/security-events` + `/api/stats/overview` (200), zero `/api/v1/logs/*` — **PENDING** (requires running stack) |
| Platform | `npm run type-check` ✅ · `npm run build` ✅ |
| Release | `rg "/api/v1/logs\|vlogs\|victoria" dist` → 0 hits ✅; `rg "/api/security-events" dist` → present ✅ |

## Harness Delta

- Surfaced that `scripts/bin/harness-cli` (cited in `AGENTS.md` as the main
  operational tool) is absent from this checkout — proof recording fell back to
  story file + git.

## Evidence

- Plan: `plans/260627-1953-a1-logs-security-events-rewire/`
- Code review: APPROVE-WITH-NITS 8.5/10; both actionable nits fixed (page_size
  clamp alignment, `rate_limit` filter restored).
- Build: `tsc --noEmit && vite build` green; `dist` grep clean of dead endpoints.
