# Fix Report: refine v5 unstable `result` deps clobbering forms/toggles

**Date:** 2026-07-06
**Plan:** `plans/260706-1028-refine-result-unstable-deps-form-clobber/`
**Branch:** main-harness

## Root Cause

refine v5 `useCustom()` returns `result: { data: ... }` rebuilt **every render, no
memoization** (verified against upstream `packages/core/src/hooks/data/useCustom.ts`).
Any `useEffect`/`useMemo` with the `result` wrapper in deps fires every render.
On the DDoS page: toggle switch → setState → re-render → hydrate effect re-fires →
`setTierEnabled`/`setFieldsValue` revert to server config → switch snaps back.
Also caused a passive re-render loop (`setTierEnabled({...})` fresh object per pass).

## Fix

One-line dep change per site: `[xxxQuery.result]` → `[xxxQuery.result?.data]`.
`result.data` IS referentially stable (react-query structural sharing; empty
fallback is a module constant). Effect/memo bodies untouched. In-repo precedent:
`pages/logs/index.tsx:93` already did this.

## Files Changed (13 sites, 9 files + 4 memo sites)

Hydration effects (form-clobber risk):
- `ddos-protection/index.tsx` — dep fix + deleted duplicate error effect
- `challenge-engine/index.tsx`, `crowdsec-settings/index.tsx`,
  `device-fingerprinting/index.tsx` (+ removed dead `dirtyRef` from abandoned
  workaround), `relay-intel/index.tsx`, `response-filtering/index.tsx` (2 sites),
  `risk-scoring/index.tsx`, `tx-velocity/index.tsx`

Memos (wasted recompute only):
- `bot-management/index.tsx`, `rule-analytics/index.tsx`,
  `rule-sources/index.tsx`, `settings/index.tsx`

Docs: created `docs/code-standards.md` with the dep convention
(plan referenced this path; file did not exist — created minimal).

## Verification

Static:
- Sweep grep for `.result`/`Result` wrapper deps: **zero remaining**
- `npx tsc --noEmit`: clean
- `npm run build`: success (1.61s)

Runtime (mock-backed E2E — no real backend available in-session: docker socket
permission denied, default.toml expects containerized Postgres):
- Mock waf-api (Node, real `{success,data}` envelope, config from current
  `configs/ddos.yaml`) on :9527 + vite dev (`VITE_API_HTTPS=false`) on :5174
- agent-browser: login → DDoS page → hydration correct (all values match mock)
- Toggled "Enable DDoS Protection" off + critical tier off + set high-tier
  per-fp threshold 123 → **held through 8s and 7s waits** spanning multiple 5s
  poll cycles (previously snapped back within one render)
- Save → PUT body exact: `enabled:false, tiers.critical:null,
  tiers.high.per_fp_threshold:123`, rest unchanged
- No refetch flood: `/api/ddos/config` GET ×3 total (initial + post-save refetch)
  vs metrics/ban-table ×18/×17 (expected 5s polling) — render loop gone

Not verified against real waf-api binary (env limitation). Contract risk low:
FE-only dep changes, no request/response shape touched.

## Deployment Caveat

Admin panel is embedded into the prx-waf binary via rust-embed. A running
container/binary serves the OLD panel until rebuilt
(`npm run build` then `cargo build` / image rebuild). Same caveat as
`plans/reports/fix-260706-0944-ddos-config-save-schema-mismatch-report.md`.

## Unresolved Questions

None.
