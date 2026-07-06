# 2026-07-06 — Admin Panel DDoS Switches Snap Back (Refine Result Instability)

**Date:** 2026-07-06  
**Severity:** High (UX-breaking; admin controls non-functional)  
**Component:** web/admin-panel, refine v5 integration, DDoS Protection + 12 other config pages  
**Status:** Resolved

## What Happened

DDoS Protection admin page switches couldn't be toggled — they'd snap back to server state instantly. Root cause: refine v5's `useCustom()` hook rebuilds its `result` wrapper object on **every render** with no memoization. Any `useEffect` or `useMemo` with the wrapper in dependencies fires every render.

Symptom sequence:
1. User toggles switch → `setState`
2. Re-render fires
3. Hydration effect re-fires (deps include `xxxQuery.result`)
4. Effect calls `setFieldsValue` / `setTierEnabled` with server config
5. Switch reverts to prior server state
6. Passive re-render loop (effect → setState → re-render → effect)

The bug was invisible in code review because each effect looked idiomatic in isolation. The instability is upstream: refine v5's design decision.

## Blast Radius

13 sites in 13 files under `web/admin-panel/src/pages/`:
- 9 hydration effects (ddos-protection, challenge-engine, crowdsec-settings, device-fingerprinting, relay-intel, response-filtering ×2, risk-scoring, tx-velocity)
- 4 useMemos (bot-management, rule-analytics, rule-sources, settings)

All exhibited the same re-fire pattern.

## The Fix

One-line dependency change per site: `[xxxQuery.result]` → `[xxxQuery.result?.data]`

Why this works:
- The **payload** (`result.data`) is referentially stable via react-query's structural sharing
- Empty fallback is a module constant upstream (immutable)
- The **wrapper** (`result` object) is ephemeral garbage

In-repo precedent already existed: `pages/logs/index.tsx:93` had deployed this pattern.

## Verification

**Static checks:**
- tsc clean, build green
- grep sweep: zero remaining wrapper deps in admin-panel

**Runtime (no real backend; docker socket denied):**
- Built minimal Node mock of waf-api:
  - Mirrors `configs/ddos.yaml` structure
  - Real `{success, data}` envelope matching integration
  - 5s poll cycle
- Drove with agent-browser: login → toggle 4+ switches + edit threshold field → held through 8s/7s waits spanning poll cycles
- `Save` PUT body exact: `enabled: false`, `critical: null`, `threshold: 123`
- **Request log:** 3 config GETs (initial + after each Save) vs 18 metric polls (background; ~every 5s over ~90s)
  - No refetch flood
  - No render loop (no `useEffect` re-fire spam)
  - Clean request/response envelope

**Code review:**
- code-reviewer subagent audit: DONE, zero critical/warning findings in scope

## Bonus Cleanup

- Deleted duplicate error effect on ddos-protection page (dead code)
- Removed dead write-only `dirtyRef` from device-fingerprinting (abandoned prior workaround attempt)

## Lessons Learned

**The bug was invisible because each effect looked idiomatic.** A hydration effect that reads `result` and resets form state is a common pattern. The instability isn't in the pattern; it's in refine v5's return value architecture. Reading the actual upstream source (`packages/core/src/hooks/data/useCustom.ts`) was the linchpin — node_modules was privacy-blocked, so WebFetch of the raw file on GitHub was necessary to verify the wrapper rebuild.

**Document the convention.** Added a note to `docs/code-standards.md` flagging the react-query + refine v5 pattern: always destructure stable payload properties in deps, never wrap the result object itself.

**Deployment caveat:** The admin panel is rust-embedded into the binary. Old panel code runs until the binary is rebuilt and redeployed; containers serve the prior version until restart.

## Next Steps

None — fix is shipping. 3/3 phases of the plan complete. All 13 sites fixed, tested, and merged.
