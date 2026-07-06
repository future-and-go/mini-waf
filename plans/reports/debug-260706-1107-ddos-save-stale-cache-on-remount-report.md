# Debug Report: DDoS page shows pre-save state after navigating away and back

**Date:** 2026-07-06 11:07
**Symptom:** Toggle switch → Save → "saved successfully" → navigate to another page → back to DDoS page → state reverts to first-load values. Hard refresh shows saved values.

## Root Cause

Two compounding facts, both in source:

1. **Save never updated the client cache.** `ddos-protection/index.tsx` save
   `onSuccess` only showed a message — no `configQuery.refetch()`. The unban
   handler and every other config page (challenge-engine, crowdsec, device-fp,
   relay-intel, tx-velocity) already refetch on save; this page didn't.
2. **Global `staleTime: 30_000`** (`src/hooks/use-query-client.ts:15`); the
   config query doesn't override it. Navigate away → back within 30s → react-query
   serves the cached **pre-save** GET payload as fresh, zero network — the hydrate
   effect faithfully hydrates stale cache. Hard refresh wipes the in-memory cache
   → fresh GET → correct values.

Latent until now: before the dep fix (plan 260706-1028) the switches couldn't be
toggled at all, so save-then-navigate was unreachable.

## Fix (3 sites, same missing-refetch gap found by audit)

Add refetch to save `onSuccess`, matching in-repo pattern:
- `ddos-protection/index.tsx` → `configQuery.refetch()`
- `risk-scoring/index.tsx` → `configQuery.query.refetch()` (same latent bug)
- `response-filtering/index.tsx` host-filter save → `hostFilterQuery.query.refetch()`
  (its other save already refetched)

## Verification

- `npx tsc --noEmit` clean; `npm run build` green.
- E2E (mock waf-api now persists PUT + vite dev + agent-browser), user's exact
  flow: login → DDoS → toggle "Enable DDoS Protection" off → Save → navigate to
  Device Fingerprinting → back to DDoS within staleTime → switch shows
  **checked=false (saved state)**. Request trace: `PUT /api/ddos/config
  (enabled:false)` immediately followed by `GET /api/ddos/config` (the new
  refetch) — cache updated, remount hydrates saved values.

## Deployment

Panel is rust-embedded; rebuild binary/container (`npm run build` + cargo/image
rebuild) or the running instance keeps serving the old panel.

## Unresolved Questions

None.
