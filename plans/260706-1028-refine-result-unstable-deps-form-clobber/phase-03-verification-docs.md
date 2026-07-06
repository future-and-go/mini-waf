---
phase: 3
title: Verification & Docs
status: completed
priority: P2
dependencies:
  - 1
  - 2
---

# Phase 3: Verification & Docs

## Overview

Prove the fix panel-wide, guard against pattern regression with a documented
convention, and surface the deployment caveat.

## Requirements

- Functional: build green, no type errors, runtime behavior verified on the
  reported page.
- Non-functional: future pages don't reintroduce the wrapper-dep pattern.

## Related Code Files

- Modify: `docs/code-standards.md` (add refine v5 `useCustom` dep convention)
- No product-code changes in this phase beyond fixes fallout, if any.

## Implementation Steps

1. `cd web/admin-panel && npx tsc --noEmit` → clean.
2. `npm run build` → succeeds.
3. Runtime verification (dev server against running waf-api, or rebuilt
   container): on ddos-protection, toggle each switch class (enabled, tier,
   redis), hold >5s under polling, Save, Reload, confirm round-trip through
   `configs/ddos.yaml`.
4. Spot-check one form page (risk-scoring) and one memo page (rule-analytics)
   for normal behavior.
5. Append a short convention note to `docs/code-standards.md`:
   "refine v5 `useCustom().result` is rebuilt every render — never put the
   wrapper in effect/memo deps; depend on `result?.data`." Keep ≤6 lines;
   respect docs.maxLoc 800.
6. Write completion report to
   `plans/reports/fix-260706-refine-result-unstable-deps-form-clobber-report.md`
   (summary, files touched, verification evidence, deployment caveat).

## Success Criteria

- [x] tsc + build green.
- [x] DDoS page switch behavior verified end-to-end (the original user symptom).
      (Mock-backed E2E: real envelope + config, agent-browser login → toggle →
      held through poll cycles → Save PUT body exact. Real-binary run not possible
      in-session: docker socket denied, config expects containerized Postgres.)
- [x] `docs/code-standards.md` note added.
- [x] Report written; deployment caveat (rust-embed container rebuild) stated.

## Risk Assessment

- If runtime verification is impossible in-session (no running backend),
  document that limitation in the report and verify via `npm run dev` +
  mocked/real API as available; do not claim unverified behavior.
