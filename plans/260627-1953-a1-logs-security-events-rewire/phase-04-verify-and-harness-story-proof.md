---
phase: 4
title: "Verify and harness story proof"
status: pending
priority: P2
effort: "1h"
dependencies: [1, 2, 3]
---

# Phase 4: Verify and harness story proof

## Overview
End-to-end verification of the rewired Logs page and recording of harness proof
under epic E12, per `docs/FEATURE_INTAKE.md` (normal lane) and the A1 §10 intake.

## Requirements
- Functional: full FE build passes; Network-tab proof that the Logs page uses
  only `/api/security-events` (+ `/api/stats/overview`); no `/api/v1/logs/*`.
- Non-functional: durable proof recorded in the harness; story file linked.

## Architecture
- This is a verification + bookkeeping phase, no new product code.
- Story packet under `docs/stories/epics/E12-audit-log/` from
  `docs/templates/story.md`; link `docs/product/audit-log.md`.
- **`scripts/bin/harness-cli` is not present in this checkout** (verified — no
  `scripts/bin` dir). Record proof **manually**: write the build/network-tab
  evidence into the story markdown and commit it. Do not block on the missing
  binary. If a harness-cli appears later, backfill `story add/update`.
  <!-- Updated: Validation Session 1 - manual story + git proof; harness-cli absent -->

## Related Code Files
- Create: `docs/stories/epics/E12-audit-log/US-12xx-logs-page-rewire.md`
- Read: `docs/templates/story.md`, `docs/product/audit-log.md`

## Implementation Steps
1. Run `pnpm build` in `web/admin-panel`; confirm green.
2. Manual proof: open Logs page, capture Network tab showing only
   `/api/security-events` and `/api/stats/overview` calls (200), zero
   `/api/v1/logs/*`.
3. `rg "/api/v1/logs|vlogs|victoria" web/admin-panel/src web/admin-panel/dist`
   → no hits.
4. Create the E12 story file (`docs/stories/epics/E12-audit-log/US-12xx-logs-page-rewire.md`)
   from `docs/templates/story.md`; paste the build + Network-tab proof into it
   and commit. (No `harness-cli` — record proof in the story file + git.)
5. Note explicitly in the story that this closes the **GUI** view only — true
   FR-032 (SIEM JSONL read API) remains a deferred high-risk follow-up.

## Success Criteria
- [ ] `pnpm build` green.
- [ ] Network-tab proof attached; zero `/api/v1/logs/*` calls.
- [ ] grep residue check clean across `src` and `dist`.
- [ ] E12 story file created with proof pasted in and committed (no harness-cli).
- [ ] Story states FR-032 SIEM feed is NOT closed by this change.

## Risk Assessment
- Mistaking the GUI fix for FR-032 completion → mitigated by step 5's explicit
  note. Retention/rotation of `waf_audit.log` is out of scope (track in E12).
