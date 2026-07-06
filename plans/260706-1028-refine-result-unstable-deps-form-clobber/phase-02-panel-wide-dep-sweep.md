---
phase: 2
title: Panel-Wide Dep Sweep
status: completed
priority: P2
dependencies:
  - 1
---

# Phase 2: Panel-Wide Dep Sweep

## Overview

Apply the same one-line dependency fix to the remaining 12 unstable-dep sites so
form hydration stops clobbering unsaved edits and memos stop recomputing every
render. Uniform mechanical change; effect/memo bodies untouched.

## Requirements

- Functional: unsaved form edits survive background re-renders on every config
  page; hydration still happens on first load and on explicit refetch (e.g.
  device-fp Save → `configQuery.query.refetch()`).
- Non-functional: memos recompute only when data changes.

## Architecture

Same as Phase 1: depend on the stable `result?.data` value instead of the
per-render `result` wrapper. In-repo precedent: `pages/logs/index.tsx:93`.

## Related Code Files (Modify)

Form-hydration effects:

1. `web/admin-panel/src/pages/challenge-engine/index.tsx:82` — `[configQuery.result, form]` → `[configQuery.result?.data, form]`
2. `web/admin-panel/src/pages/crowdsec-settings/index.tsx:91` — same pattern
3. `web/admin-panel/src/pages/device-fingerprinting/index.tsx:126` — `[configQuery.result]` → `[configQuery.result?.data]`; also delete the dead `dirtyRef` (declared :94, written :141/:189, **never read** — abandoned guard for this same bug, misleading)
4. `web/admin-panel/src/pages/relay-intel/index.tsx:105` — same dep fix; note `setTrustedCidrs(cfg.trusted_proxies ?? [])` fresh-array is then harmless (effect no longer re-fires)
5. `web/admin-panel/src/pages/response-filtering/index.tsx:150` — same dep fix
6. `web/admin-panel/src/pages/response-filtering/index.tsx:333` — `[hostFilterQuery.result]` → `[hostFilterQuery.result?.data]`
7. `web/admin-panel/src/pages/risk-scoring/index.tsx:138` — `[configQuery.result, configForm]` → `[configQuery.result?.data, configForm]`
8. `web/admin-panel/src/pages/tx-velocity/index.tsx:97` — `[cfgQuery.result]` → `[cfgQuery.result?.data]`

Wasted memos:

9. `web/admin-panel/src/pages/bot-management/index.tsx:145` — `[relayQuery.result, proxyQuery.result]` → `[relayQuery.result?.data, proxyQuery.result?.data]`
10. `web/admin-panel/src/pages/rule-analytics/index.tsx:285` — `[blockedEvents.result]` → `[blockedEvents.result?.data]`
11. `web/admin-panel/src/pages/rule-sources/index.tsx:99` — `[registryResult, sources]` → `[registryResult?.data, sources]` (confirm `registryResult` is the `useCustom` result alias before editing)
12. `web/admin-panel/src/pages/settings/index.tsx:196` — `[feedsQuery.result]` → `[feedsQuery.result?.data]`

Verify-only: `web/admin-panel/src/pages/logs/index.tsx:93` already `[result?.data]` — leave untouched.

## Implementation Steps

1. Apply the dep edits above, one file at a time; do not restructure bodies.
2. For each site, confirm the body reads via `xxx.result?.data` (all do, per the
   2026-07-06 audit) so dep and read stay consistent.
3. Re-run the sweep grep to prove completeness:
   `grep -rn "\.result\]\|\.result," web/admin-panel/src/pages --include=*.tsx`
   filtered to dependency arrays → zero remaining wrapper deps.
4. `react-hooks/exhaustive-deps` will not flag `result?.data` deps — no lint
   suppression needed.

## Success Criteria

- [x] All 12 sites edited; sweep grep clean.
- [x] `dirtyRef` fully removed from device-fingerprinting (declaration + both writes).
      (Code review confirmed the removed ref was write-only; zero dangling refs.)
- [x] Spot-check in dev: edit a field on risk-scoring, wait for its metrics poll
      tick, edit survives; same on device-fp; Save on device-fp still re-hydrates
      via explicit refetch.

## Risk Assessment

- Low/mechanical. Main risk: a site whose body intentionally relied on
  every-render execution — none found in the audit (all are hydrate-or-derive).
- `rule-sources` uses a destructured alias; verify alias origin before edit.
