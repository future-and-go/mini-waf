---
phase: 5
title: "Run guide + aggregation + result artifact"
status: complete
priority: P2
dependencies: [3, 4]
---

# Phase 5: Run guide + aggregation + result artifact

## Overview
Make the suite runnable and its results consumable: README run steps, wire it
into `render-report.sh` aggregation, run it, and capture the produced result
artifact as the deliverable "test result".

## Requirements
- Functional: documented one-command-ish run flow (compose up → run suite →
  render report).
- Functional: suite appears in aggregated report alongside the other suites.
- Non-functional: metrics/actors stub-exclusion caveat documented.

## Architecture
<!-- Updated: Validation Session 1 - render-report uses a hardcoded array, not a glob -->
`run-risk-config.sh` already emits `out/risk-config/{results.json,junit.xml,
summary.md}` via `lib.sh`. **VERIFIED:** `render-report.sh` does NOT
auto-discover — it iterates a hardcoded array `SUITES=(rules-engine gateway
waf-api cluster)` (line 19). Must add `risk-config` to that array explicitly.
README gains a "Risk config suite" subsection.

## Related Code Files
- Modify: `tests/e2e/README.md` (run steps + stub caveat)
- Verify/Modify: `tests/e2e/render-report.sh` (includes `out/risk-config`)
- Verify: `.github/workflows/nightly-e2e.yml` (optional: add job — note only,
  do not wire CI unless requested)
- Create (deliverable): `plans/260707-1035-risk-config-admin-ui-e2e-verification/reports/risk-config-e2e-run-results.md`

## Implementation Steps
1. Add `risk-config` to the `SUITES` array in `render-report.sh` (line 19).
2. Add README subsection: prerequisites (dedicated risk override compose), run
   commands, expected artifacts, and the "metrics/actors are stubs — excluded"
   caveat.
3. Run the full flow locally; confirm green.
4. Capture the produced `summary.md` / `results.json` into `reports/
   risk-config-e2e-run-results.md` as the recorded test result.
5. CI: leave a documented job stub in README only — do NOT wire
   `nightly-e2e.yml` yet (validated: local-only for now).

## Success Criteria
- [ ] `risk-config` added to `render-report.sh` `SUITES` array; suite appears in aggregate.
- [ ] README documents run steps + stub-exclusion caveat + CI job stub.
- [ ] Suite runs green end-to-end locally.
- [ ] Result artifact captured in `reports/`.

## Risk Assessment
- **CI scope creep** — nightly wiring is out of scope (validated local-only);
  document a job stub in README instead of editing `nightly-e2e.yml`.
- **Shared-file edit** — adding to `render-report.sh` `SUITES` touches a file all
  suites share; the change is additive (one array element), low blast radius.
