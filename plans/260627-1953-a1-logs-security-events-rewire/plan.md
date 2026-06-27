---
title: "A1 Logs Page — rewire onto /api/security-events"
description: "Repoint the broken admin-panel Logs page from the decommissioned VictoriaLogs endpoints to the live /api/security-events feed, and remove dead FE code."
status: pending
priority: P2
branch: "feat/check-miss-match-fe"
tags: [admin-panel, frontend, audit-log, E12]
blockedBy: []
blocks: []
created: "2026-06-27T19:53:00.000Z"
createdBy: "ck:plan"
source: skill
lane: normal
---

# A1 Logs Page — rewire onto /api/security-events

## Overview

The admin-panel Logs page (`web/admin-panel/src/pages/logs/`) is **broken**: it
still calls the `/api/v1/logs/*` VictoriaLogs endpoints, which were removed when
VictoriaLogs was decommissioned (E12, decision 0010) and now 404. This plan
re-points the page at the live, paginated `/api/security-events` feed — the
correct request/attack source — and deletes the dead VictoriaLogs FE code.

**Source spec:** `docs/review/admin-panel/plans/A1-logs-audit-log-rewire.md`
(Option A). **Lane:** normal (FE-only; no auth/data hard-gate).

## Key Decisions (verified)

- `/api/security-events` is live, returns `{ success, data, total }`, paginated
  via `page`/`page_size` (`SecurityEventQuery`, `crates/waf-storage/src/models.rs:323-336`).
- `SecurityEvent` carries the render fields incl. `waf_mode`
  (`models.rs:106-119`); `event_type` has no equivalent → derive from `action`
  or drop.
- An existing `pages/security-events/` page already consumes this feed — use it
  (plus `pages/tx-velocity/index.tsx`) as the canonical pattern.
- **Out of scope:** the JSONL read API over `waf_audit.log` (A1 Option B / true
  FR-032 SIEM view) — separate high-risk story under E12. This plan is the GUI
  fix only and must NOT be mistaken for FR-032 completion.

## Phases

| # | Phase | Status | Priority |
|---|-------|--------|----------|
| 1 | [Repoint logs table to security-events](phase-01-repoint-logs-table-to-security-events.md) | completed | P1 |
| 2 | [Filters and 24h entries card](phase-02-filters-and-24h-entries-card.md) | completed | P2 |
| 3 | [Remove dead VictoriaLogs FE code](phase-03-remove-dead-victorialogs-fe-code.md) | completed | P2 |
| 4 | [Verify and harness story proof](phase-04-verify-and-harness-story-proof.md) | in-progress | P2 |

**Status note (2026-06-27):** Phases 1–3 implemented; `tsc --noEmit` + `vite build`
green; `dist` grep clean of `/api/v1/logs`/`vlogs`/`victoria`. Code review
APPROVE-WITH-NITS 8.5/10, both nits fixed (page_size clamp, `rate_limit` filter).
Story `docs/stories/epics/E12-audit-log/US-1206-logs-page-rewire.md` created.
Phase 4 remaining: manual Network-tab proof against a running stack.

## Dependencies

- E12 JSONL sink + VictoriaLogs decommission (`plans/260615-1509-e12-audit-log-jsonl-sink/`)
  — **completed**; this plan is the FE cleanup that the decommission left pending.

## Deferred follow-up (NOT in this plan)

- `GET /api/audit-log/query` JSONL read API for true FR-032 / SIEM view. Reads a
  server file → audit/security hard-gate → high-risk story packet + decision
  under E12. Track separately.

## Validation Log — 2026-06-27 (Session 1)

### Verification Results
- Tier: Standard (4 phases). Claims checked: ~12 · Verified: 9 · Failed/Gaps: 3.
- Verified: `/api/stats/overview` + `hours` param (`server.rs:200`, `stats.rs:53–59`);
  `LogRow` `_time`/`event_type`/`tier` optional (`LogsTable.tsx:25–44`); vlogs at
  `App.tsx:13,74,124` + `index.tsx:104,194`; `SecurityEvent`/`SecurityEventQuery`
  incl. `waf_mode` (`models.rs:106–119,323–336`).
- Failures resolved into phases:
  - **Gap 1** — `App.tsx:74` `logs` resource `meta.dataProviderName:"vlogs"` was
    unaddressed → added to Phase 3.
  - **Gap 2** — `scripts/bin/harness-cli` absent (no `scripts/bin` dir) → Phase 4
    switched to manual story + git proof.
  - **Minor** — disabled-state heuristic (`index.tsx:142–147`) folded into Phase 3.

### Decisions (user-confirmed)
- `logs` resource: keep route/nav at `/logs`, drop vlogs meta, `useList` overrides
  `resource:"security-events"`.
- Proof: manual E12 story file + git (no harness-cli).
- 24h card: keep, wire to `GET /api/stats/overview?hours=24`.
- LogsQueryBar: remove (LogsQL has no security-events equivalent).

### Whole-Plan Consistency Sweep
- Re-read plan.md + all 4 phase files. No stale "convert query bar", no
  remaining `harness-cli`-as-available claim, no `/api/v1/logs/*` "works"
  assertion. `resource:"security-events"` override consistent across Phases 1/3.
  Zero unresolved contradictions.
