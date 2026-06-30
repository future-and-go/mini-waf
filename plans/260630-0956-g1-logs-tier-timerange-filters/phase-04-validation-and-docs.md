---
phase: 4
title: "Validation, story + decision record, build/test proof"
status: done
priority: P2
dependencies: [1, 2, 3]
---

# Phase 4: Validation, story + decision record, build/test proof

## Overview
Satisfy the intake lane (Data-model + Existing-behavior flags): record a durable
decision for persisting tier to Postgres, a story for the filter restoration, and
capture end-to-end proof.

## Requirements
- Functional: documented decision + story; passing tests; manual end-to-end proof of
  both filters against a running stack.
- Non-functional: docs match the actual change (dates, file paths, field names).

## Architecture
Per `docs/FEATURE_INTAKE.md`, a schema/data-ownership change warrants a decision record;
story-sized behavior warrants a story file. Validation expectations are unit + manual.

## Related Code Files
- Create:
  - `docs/decisions/00NN-persist-tier-on-security-events.md` (from
    `docs/templates/decision.md`) — why tier is persisted to Postgres, forward-only
    consequence, Debug-format choice (D3), relationship to JSONL/FR-032.
  - `docs/stories/.../US-12NN-restore-logs-tier-time-range-filters.md` (from
    `docs/templates/story.md`) — scope, acceptance, validation status.
- Modify (if claims change): `docs/journals/2026-06-27-a1-logs-page-security-events-rewire.md`
  is a record — do not rewrite; reference it from the new story instead.

## Implementation Steps
1. Write the decision record. It MUST cover:
   - Data ownership: `tier` now persisted on `security_events` (forward-only).
   - **NULL-tier behavior (finding 6):** pre-migration rows have `tier = NULL` and are
     excluded whenever a tier filter is active — a deliberate Existing-behavior change
     (intake flag) requiring this recorded sign-off, not a planner assertion. Note the
     deferred option of an "Unknown (pre-tier)" bucket (`tier IS NULL`) if users need it.
   - Format contract (finding 8): tier stored as Debug PascalCase; do NOT switch to serde
     serialization without updating the FE strings + the pinning test.
2. Write the story file linking predecessor rewire + this plan; record the deploy-order
   constraint (below), the NULL-tier behavior, and the **default-range change** (the page
   now loads last-1h instead of all-time — D1, validation session 1) so QA does not
   misfile either as a regression.
3. Add an FE hint (finding 6): when a tier filter is active, show an inline note that
   events created before the tier rollout have no tier and are excluded. (Small copy
   change in `LogsFilters`/`index.tsx`; keep it lightweight.)
4. Run focused backend tests (`cargo test -p waf-storage -p waf-engine -p waf-api`) and
   FE build (`tsc --noEmit`, `vite build`).
5. Manual proof against a running stack: generate events at >1 tier **through the batch
   writer path** (the default prod path), then:
   - confirm new rows have non-null tier (`SELECT count(*) ... WHERE tier IS NULL AND
     created_at > <start>` = 0);
   - confirm `created_at_from/to` (Z-suffixed) and `tier=Critical,High` narrow the table
     and pager `total`; clearing tier returns to unfiltered;
   - confirm pagination still works WITH a time filter (catches the `$N`/LIMIT bug).
   Capture Network-tab params + before/after counts in the story.
6. **Authz + error-leak guard (fold-in, finding 12):** add a regression assertion that
   `GET /api/security-events` returns 401 without a JWT (route currently behind
   `require_auth`+admin-IP+rate-limit, `server.rs:313-321` — guard against a future
   refactor moving it out). Confirm `ApiError` (`waf-api/src/error.rs`) does not serialize
   raw `StorageError`/SQL text into the HTTP response body.
7. If `scripts/bin/harness-cli` is present, record story/decision via
   `harness-cli story add|update` and `harness-cli decision add`; if absent (it was
   missing in the predecessor checkout), record proof in the story file + git.

## Deploy Ordering (finding 7)
Two independent artifacts ship (Rust binary+migration vs. FE bundle). Required order:
**backend fully rolled out before the FE bundle that exposes the tier/time filters.**
- FE-first → an old backend silently drops the unknown `tier` param (serde ignores
  unknown query keys) → filter no-ops, looks broken.
- During a rolling backend deploy, old nodes write NULL tier until all nodes are new →
  recent events transiently vanish under a tier filter. Document the rollout window;
  optionally gate the FE filter behind a capability check.

## Success Criteria
- [ ] Decision + story files written and internally consistent with the code, incl. the
      NULL-tier behavior sign-off (finding 6), format contract (finding 8), and deploy
      order (finding 7).
- [ ] FE inline hint shown when a tier filter is active (finding 6).
- [ ] `cargo test` (touched crates) green.
- [ ] `tsc --noEmit` + `vite build` green.
- [ ] 401-without-JWT regression assertion passes; `ApiError` confirmed not to leak raw
      SQL (finding 12).
- [ ] Manual end-to-end proof captured through the **batch path** (params, before/after
      counts, NULL-tier exclusion, pagination-with-time-filter).

## Risk Assessment
- **Unverifiable claims:** the predecessor journal showed several plan claims were wrong
  vs. source. Mitigation: every load-bearing line/field here was scout-verified, but the
  implementer must re-confirm `repo.rs` line numbers and the `db_batch_writer` insert at
  edit time (line numbers drift).
- **harness-cli absence:** tooling may be missing in this checkout. Mitigation: fall back
  to file + git proof, as the predecessor did.
