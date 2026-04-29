# Phase 06 — Docs + Sample Rules

**Status:** done  **Priority:** P1  **Effort:** 0.25d  **ACs:** docs only

## Context Links
- Design: brainstorm §3.3, §6 (risk row 3)
- Touch: `rules/custom/*.yaml`, `rules/README.md` (or `docs/rules-syntax.md`), `docs/codebase-summary.md`

## Overview
Document new schema, glob semantics, cookie-by-name, and migration notes. Add 2–3 sample YAML rules under `rules/custom/` exercising wildcard + nested AND/OR so reviewers see runnable artifacts.

## Requirements
1. `rules/README.md` (or `docs/rules-syntax.md`): full schema reference — fields, operators, glob syntax, cookie name, nested example.
2. Sample rules:
   - `rules/custom/sample-wildcard-admin.yaml` (AC-3)
   - `rules/custom/sample-nested-blacklist.yaml` (AC-8)
   - `rules/custom/sample-cookie-session.yaml` (AC-6)
3. Migration note: legacy flat rules continue to work — no action required.
4. Update `docs/codebase-summary.md` rule-engine section with new architecture (Composite + Strategy, link to brainstorm).

## Related Code Files
**Create:** sample YAMLs above.
**Modify:** `rules/README.md`, `docs/codebase-summary.md`.

## Implementation Steps
1. Draft schema reference markdown (under 200 LoC).
2. Write 3 sample rules — each with a comment explaining intent.
3. Verify `cargo run -- run` (or hot-reload trigger) loads them without warnings.
4. Update codebase-summary.md.

## Todo
- [x] `docs/custom-rules-syntax.md` schema doc (rules/README.md is for a different schema — registry Rule format; new doc covers the FR-003 CustomRule engine)
- [x] 3 sample rules under `rules/custom/fr003-samples/` (JSON wire format — DB/API-driven; YAML registry loader handles a separate schema)
- [~] Hot-reload smoke test — N/A: samples target the DB/API-driven engine, not the file watcher
- [x] `docs/codebase-summary.md` update

## Success Criteria
- Sample rules load on hot-reload, no warn logs.
- Schema doc covers every operator + nesting + cookie-by-name.
- New developer can write a custom rule by reading docs alone.
