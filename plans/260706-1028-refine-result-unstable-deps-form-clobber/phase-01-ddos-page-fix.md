---
phase: 1
title: DDoS Page Fix
status: completed
priority: P1
dependencies: []
---

# Phase 1: DDoS Page Fix

## Overview

Fix the confirmed user-facing bug: switches on the DDoS protection page cannot
be changed because the config-hydration effect re-fires every render and reverts
all local state, plus an infinite passive-effect re-render loop.

## Requirements

- Functional: all switches (enabled, hot_reload, 4× tier, redis) toggle and hold
  their value; form inputs editable; Save/Reload behavior unchanged.
- Non-functional: no continuous re-render loop; hydration fires once per fetch.

## Architecture

`configResult` (`useCustom().result`) is a fresh wrapper object each render;
`configResult?.data` is referentially stable (react-query structural sharing).
Switching the effect dependency to the stable value makes the hydrate effect
fire only when fetched config actually changes — which also dissolves the
infinite loop caused by `setTierEnabled({...})` running every render.

## Related Code Files

- Modify: `web/admin-panel/src/pages/ddos-protection/index.tsx`

## Implementation Steps

1. Line 251: change effect deps `[configResult]` → `[configResult?.data]`.
   Body (lines 228–250) stays as-is.
2. Lines 253–259: two duplicate effects both set `endpointMissing` on config
   error (`configQuery.isError` and `configQuery.error`). Delete one (keep the
   `isError` variant — matches the metrics-error effect at line 213). This
   duplicate was introduced in the same uncommitted working-tree diff, so it is
   in-scope cleanup, not adjacent-code drift.
3. Manual runtime check (dev server or rebuilt container): toggle a tier switch,
   wait >5s with metrics poll running — switch must hold. Toggle `enabled` off,
   Save, Reload — persisted state must round-trip via `configs/ddos.yaml`.

## Success Criteria

- [x] Tier/redis/enabled/hot_reload switches toggle and hold for >5s under polling.
      (E2E: enabled + critical-tier switches held through 8s spanning poll cycles.)
- [x] No render loop: renders occur only on poll ticks/user input (verify via
      React DevTools profiler or temporary render log — remove before commit).
      (Verified via request pattern instead: config GET ×3 total vs 5s polls ×18.)
- [x] Save → success message → Reload shows saved values.
      (PUT body exact: enabled:false, critical:null, threshold 123. Server-side
      persistence round-trip previously verified in fix-260706-0944 report.)
- [x] Single config-error effect remains; `endpointMissing` alert still appears
      when GET /api/ddos/config fails.

## Risk Assessment

- Low. One dep change + duplicate-effect removal. Post-save re-hydration still
  works because Save success does not refetch config on this page (values remain
  what the user submitted); Reload button explicitly refetches.
