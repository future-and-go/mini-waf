# A1: Logs Page Rewired onto /api/security-events

**Date:** 2026-06-27
**Severity:** Medium
**Component:** admin-panel (frontend), audit-log (E12)
**Status:** Implemented (Phase 4 manual proof pending); uncommitted

## What Happened

The admin-panel "Security Logs" page was broken since the VictoriaLogs
decommission (E12 / decision 0010): it still called `/api/v1/logs/{query,stats,
streams}`, which were removed and now 404. Rewired the page onto the live
`/api/security-events` feed via the default Refine data provider, removed the
dead VictoriaLogs FE code, and recorded the work as story US-1206.

## The Brutal Truth

The original A1 spec said "re-point at `/api/audit-log`" — which was wrong:
that endpoint serves admin-action history, not the request/attack feed. Caught
that during the `/ask` review and pivoted to `/api/security-events` (the same
source the dashboard and the canonical security-events page already use).

The implementation looked like a trivial provider swap but wasn't. Reading the
actual `SecurityEventQuery` revealed the endpoint has **no time-range, tier, or
free-text param** — 3 of the page's 6 filters had no backend. A naive repoint
would have left the prominent date picker silently doing nothing on a
server-paginated table. Stopped and asked the user rather than ship dead UI;
decision was to remove the unsupported controls. The pagination model also had
to flip from client-slice (`mode:"off"`) to true server pagination, which
forced controlled `total`/`currentPage` wiring into LogsTable.

## Technical Details

**Data flow:**
- `useList<SecurityEvent>({resource:"security-events"})` → default provider →
  `/api/security-events?page&page_size&<filters>`; envelope `{data,total}`.
- One typed boundary mapper `toLogRow(SecurityEvent): LogRow` (parse-first):
  `created_at→_time`, `action→event_type`, `host_code→host`; `waf_mode`/
  `country` ride along as discoverable columns. No `any`.
- 24h card: `useCustom<StatsOverview>("/api/stats/overview?hours=24")` →
  `total_requests` (same KPI source as the dashboard). No fabricated number.

**Filters (mapped to real SecurityEventQuery fields only):** action, rule_name,
client_ip, host_code, path(contains). Removed: time-range + presets, tier
multi-select, free-text search, and the `/api/v1/logs/streams` dropdown fetch.

**Verified against source, not docs:**
- `security_events.action` persisted values are exactly
  `block|allow|log_only|redirect|challenge|rate_limit|timeout|circuit_breaker`
  (`crates/waf-engine/src/engine.rs:978-987`). Code review worried `log_only`
  might really be `log` (from the unrelated `RuleAction` type) — source proved
  the dropdown values correct. Restored `rate_limit` (a real value) after first
  dropping it.
- Backend clamps `page_size` to 100 (`repo.rs:1858`) → capped the FE pager
  options at `[50,100]` (was `[50,100,500]`, which would desync the pager).

**Deleted:** `pages/logs/LogsQueryBar.tsx` (LogsQL bar — no security-events
equivalent), `providers/victoria-logs-data-provider.ts`. Removed the `vlogs`
provider registration, import, and the `logs` resource's `dataProviderName`
meta in `App.tsx`.

## Proof

- `tsc --noEmit` + `vite build` green; `dist` grep: 0 `/api/v1/logs|vlogs|
  victoria`, `/api/security-events` present.
- Code review: APPROVE-WITH-NITS 8.5/10; both nits fixed.

## Lessons

- A plan citing line numbers and endpoint names is a hypothesis, not truth —
  every load-bearing claim here (`waf_mode`, action values, page_size clamp,
  `/api/audit-log` semantics) had to be checked against live source, and
  several were wrong.
- "Repoint the data source" hid a UX decision (3 dead filters). Surfacing it to
  the user beat silently shipping inert controls.

## Open / Deferred

- Manual Network-tab proof against a running stack (Phase 4) — not done here.
- True FR-032 (SIEM JSONL read API over `waf_audit.log`) — deferred high-risk
  follow-up under E12, NOT delivered by this GUI fix.
- Stale comment in `components/admin-only.tsx:17` references `/api/v1/logs/*`
  (out of scope; flagged).
- `scripts/bin/harness-cli` (cited in AGENTS.md) is absent from this checkout —
  proof recorded in the story file + git instead.
