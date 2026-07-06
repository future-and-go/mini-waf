---
title: Fix refine v5 unstable result deps clobbering admin-panel forms
description: >-
  useCustom().result is rebuilt every render; effects depending on it re-hydrate
  forms/state every render, freezing switches (DDoS page) and clobbering unsaved
  edits panel-wide. Fix: depend on stable result?.data.
status: completed
priority: P1
branch: main-harness
tags:
  - admin-panel
  - frontend
  - refine-v5
  - bugfix
blockedBy: []
blocks: []
created: '2026-07-06T03:29:55.440Z'
createdBy: 'ck:plan'
source: skill
---

# Fix refine v5 unstable result deps clobbering admin-panel forms

## Overview

**Root cause (confirmed against refine v5 source):** `useCustom()` returns
`result: { data: queryResponse.data?.data || EMPTY_OBJECT }` — a **fresh object
every render**, no memoization. Any `useEffect`/`useMemo` with `xxxQuery.result`
(or a destructured alias) in its dependency array fires on **every render**,
not once per fetch.

**Confirmed symptom (user report):** on `ddos-protection`, toggling any switch
triggers a re-render → hydrate effect re-fires → `setTierEnabled`/`setFieldsValue`
revert everything to server config → switch snaps back instantly. The effect also
calls `setTierEnabled({...})` with a fresh object literal each pass →
**infinite passive-effect re-render loop** once config loads.

**The fix (uniform, one line per site):** `result.data` IS referentially stable
(react-query structural sharing; `EMPTY_OBJECT` is a module constant). Change deps
from the wrapper to the value: `[xxxQuery.result]` → `[xxxQuery.result?.data]`.
Effect then fires exactly once per actual data change. No effect bodies change.
`logs/index.tsx:93` already uses this correct form — it is the in-repo precedent.

**Rejected alternatives:** hydrate-once ref (more code, blocks post-save re-hydrate);
dirty-flag guard (device-fp has a dead, never-read `dirtyRef` from a prior
abandoned attempt); shared `useStableResult` hook (YAGNI — 13 one-line edits).

## Affected sites (complete grep sweep, 2026-07-06)

Form/state-clobbering hydration effects (user-visible bugs):

| File:line | Clobbers |
|---|---|
| `pages/ddos-protection/index.tsx:251` | form + tierEnabled/redisEnabled state; infinite loop |
| `pages/challenge-engine/index.tsx:82` | form |
| `pages/crowdsec-settings/index.tsx:91` | form |
| `pages/device-fingerprinting/index.tsx:126` | form + storeBackend state |
| `pages/relay-intel/index.tsx:105` | form + trustedCidrs state (`?? []` fresh-array loop risk) |
| `pages/response-filtering/index.tsx:150` | form |
| `pages/response-filtering/index.tsx:333` | form |
| `pages/risk-scoring/index.tsx:138` | form + canaryPaths state (`?? []` fresh-array loop risk) |
| `pages/tx-velocity/index.tsx:97` | form + loaded state |

Wasted `useMemo` (recompute + fresh array every render; perf/render churn only):

| File:line |
|---|
| `pages/bot-management/index.tsx:145` |
| `pages/rule-analytics/index.tsx:285` |
| `pages/rule-sources/index.tsx:99` |
| `pages/settings/index.tsx:196` |

Already correct (verify only): `pages/logs/index.tsx:93` (`[result?.data]`).

## Intake

Lane: normal. Flags: existing behavior (all config pages), weak proof (no FE
tests for hydration). No hard gates — FE-only, no contract/schema change.
Backend untouched.

## Phases

| Phase | Name | Status |
|-------|------|--------|
| 1 | [DDoS Page Fix](./phase-01-ddos-page-fix.md) | Completed |
| 2 | [Panel-Wide Dep Sweep](./phase-02-panel-wide-dep-sweep.md) | Completed |
| 3 | [Verification & Docs](./phase-03-verification-docs.md) | Completed |

## Dependencies

- None blocking. Related history: `plans/reports/fix-260706-0944-ddos-config-save-schema-mismatch-report.md`
  (fixed the PUT 400; this plan fixes the remaining frozen-switch symptom on the
  same page). DDoS page changes land on top of the uncommitted working-tree diff.

## Acceptance Criteria

- [x] All switches/inputs on ddos-protection hold their toggled value while the
      5s metrics/ban-table polls run; no render loop (React DevTools profiler or
      console render counter shows renders only on poll ticks).
      (Verified via mock-backed E2E: toggles + field edit held through 8s/7s waits;
      request log shows config GET ×3 vs metrics ×18 — no refetch flood.)
- [x] All 13 fixed sites depend on `result?.data` (or equivalently stable value);
      grep for `\.result\]` / `\.result,` / `[configResult]` in effect/memo deps
      returns zero matches under `web/admin-panel/src/pages`.
- [x] Unsaved form edits on challenge-engine / risk-scoring / device-fp survive a
      background poll re-render; Save → refetch still re-hydrates the form.
      (Mechanism proven E2E on ddos-protection; named pages verified statically —
      identical dep pattern, confirmed by code review.)
- [x] `npx tsc --noEmit` clean; `npm run build` succeeds.

## Deployment note

Admin panel is embedded via rust-embed — the running `prx-waf` container must be
rebuilt for the fix to reach the deployed UI.

## Open questions

None — root cause verified from refine v5 source; fix pattern proven by the
already-correct `logs/index.tsx:93` site.
