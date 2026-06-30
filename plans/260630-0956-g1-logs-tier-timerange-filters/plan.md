---
title: "Restore tier + time-range filters on the Security Logs page"
status: done
created: 2026-06-30
branch: feat/resolve-gap-item-G1-Logs-123
scope: project
blockedBy: []
blocks: []
related:
  - plans/260627-1953-a1-logs-security-events-rewire   # predecessor rewire that stripped these filters
  - docs/journals/2026-06-27-a1-logs-page-security-events-rewire.md
intake_lane: normal-with-strong-validation   # Data-model + Existing-behavior flags (borderline high-risk)
---

# Restore tier + time-range filters on the Security Logs page

## Problem

The 2026-06-27 rewire (A1) repointed the admin-panel "Security Logs" page from the
decommissioned VictoriaLogs API onto the live Postgres-backed `/api/security-events`
feed. Three filters had no backing on that endpoint and were removed: **time-range**,
**tier**, and **free-text search**. This plan brings back **time-range** and **tier**
by extending the Postgres path. Free-text search is **out of scope** (dropped by user).

## Approach (decided in brainstorm — Approach A)

Persist `tier` into the Postgres `security_events` table (the value is already
computed per-request as `ctx.tier`, currently only written to the JSONL audit log),
then extend `SecurityEventQuery` with time-range and tier filters. This keeps the
existing indexed + server-paginated query path and avoids the deferred high-risk
JSONL read API (FR-032).

**Rejected alternatives:** (B) build a query API over the write-only `waf_audit.log`
JSONL — oversized, deferred high-risk; (C) ship time-range only and defer tier —
leaves out the field the user specifically wants.

## Resolved decisions (reversible)

- **D1 — Default time range:** **last 1 hour** on page load (validation session 1 —
  matches the original pre-rewire UX, and bounds the common-case `COUNT(*)` cost,
  finding 11). Presets (1h/6h/24h/7d) and the range picker adjust it. This is a deliberate
  change from the current rewired page (which shows all-time); record it as an
  Existing-behavior note alongside finding 6.
- **D2 — Tier multi-select encoding:** comma-joined query param `tier=Critical,High`,
  matched in SQL via `= ANY(string_to_array($N, ','))`. Avoids repeated-key `Vec`
  deserialization in axum `Query<>`.
- **D3 — Tier string format:** store the Debug-formatted enum (`Critical`, `High`,
  `Medium`, `CatchAll`) to match exactly what the JSONL already writes
  (`format!("{:?}", ctx.tier)` — note that expression lives in the `AuditEvent` literal at
  `engine.rs:1065`, a *different* struct/function from the Postgres `CreateSecurityEvent`
  at `:989` which this plan newly populates). FE multi-select sends these exact PascalCase
  strings. **Fragility (red-team finding 8):** `Tier` also derives serde
  `rename_all="snake_case"` (`catch_all`); a future switch to serde serialization would
  silently break the FE equality. Pinned by a Debug-format unit test (Phase 1) + a
  decision-record note forbidding the switch (Phase 4).

## Phases

| # | Phase | Depends on | Key files |
|---|-------|-----------|-----------|
| 1 | Persist `tier` to `security_events` (write path + schema) | — | migration 0019 (+ index migr.), models.rs, repo.rs:427 **single** + repo.rs:492-505 **batch (prod path)**, engine.rs:989, db_batch_writer.rs test literals, test fixtures |
| 2 | Extend `SecurityEventQuery` — time-range + tier (read path) | 1 | models.rs:322, repo.rs:1853 query builder, repo tests |
| 3 | Restore tier + time-range filter UI | 2 (API contract) | web/admin-panel/src/pages/logs/* |
| 4 | Validation, story + decision record, build/test proof | 1,2,3 | docs/stories, docs/decisions, tests |

## Acceptance criteria (whole plan)

- New security events persist a non-null `tier` **through the batch-writer path** (the
  production path, not just the single-insert fallback); pre-migration rows are
  `tier = NULL`.
- `GET /api/security-events?created_at_from=…&created_at_to=…` narrows results to the
  inclusive timestamp window; `tier=Critical,High` narrows to those tiers (NULL-tier rows
  excluded when the tier filter is active — a recorded Existing-behavior decision, Phase 4
  finding 6); empty `tier=` behaves as no filter.
- `total` and pagination stay correct with the new filters applied; `page_size`
  clamp (≤100) and `ORDER BY created_at DESC` unchanged.
- Frontend: range picker + 1h/6h/24h/7d presets and tier multi-select render, map to
  the new params, and the table reflects filtered results; tier column shown.
- `cargo test` (touched crates) + `tsc --noEmit` + `vite build` green.

## Out of scope

Free-text search; JSONL read API (FR-032); backfilling historical `tier`; the deleted
`LogsQueryBar`/raw-LogsQL editor; the `/api/v1/logs/streams` dynamic-options endpoint.

## Red Team Review

### Session — 2026-06-30
**Findings:** 14 (all accepted). 1–7 applied as full fixes; 8–14 folded into phase risk
notes per user decision.
**Severity breakdown:** 3 Critical, 4 High, 5 Medium, 2 Low.
**Reviewers:** Security Adversary, Assumption Destroyer, Failure Mode Analyst (each backed
findings with `file:line` evidence; SQL-injection and authz attack surfaces verified
absent — route is behind `require_auth`+admin-IP+rate-limit).

| # | Finding | Severity | Disposition | Applied To |
|---|---------|----------|-------------|------------|
| 1 | tier written to wrong struct (AuditEvent @1065 vs CreateSecurityEvent @989) | Critical | Accept (full) | Phase 1 |
| 2 | batch insert (repo.rs:492-505) is prod path; silent-drop on mismatch | Critical | Accept (full) | Phase 1 |
| 3 | `$N`/`LIMIT $10 OFFSET $11` param collision; no shared WHERE fragment | Critical | Accept (full) | Phase 2 |
| 4 | FE `SecurityEvent` type lacks `tier` → `tsc` error | High | Accept (full) | Phase 3 |
| 5 | non-concurrent `CREATE INDEX` locks table at auto-migrate boot | High | Accept (full) | Phase 1 |
| 6 | NULL-tier hides all history on tier select; needs recorded decision + FE hint | High | Accept (full) | Phase 4 |
| 7 | deploy ordering (FE-before-backend drops param; rolling NULL-tier) | High | Accept (full) | Phase 4 |
| 8 | Debug vs serde tier-string drift | Medium | Accept (note+test) | Phase 1, D3 |
| 9 | empty `tier=` returns zero rows | Medium | Accept (note) | Phase 2/3 |
| 10 | `LogsColumnsPicker.tsx` registration omitted | Medium | Accept (note) | Phase 3 |
| 11 | `COUNT(*)` cost over wide ranges (bounded by last-1h default after validation) | Medium | Accept (doc) | Phase 2 |
| 12 | authz/error-leak regression guard | Medium | Accept (guard) | Phase 4 |
| 13 | RFC3339 `+`→space urlencode trap | Low | Accept (contract) | Phase 2/3 |
| 14 | WS broadcast divergence (downgraded: page uses REST polling) | Low | Accept (doc) | Phase 3 |

### Whole-Plan Consistency Sweep
Re-read all phase files after applying 1–7. Reconciled: every `repo.rs:427`-only / single
write-path reference now names the batch path (`repo.rs:492-505`) as primary; the
`engine.rs:1065` "reuse" framing replaced with the correct `:989`/`CreateSecurityEvent`
target; "shared WHERE fragment" claim corrected to "two independent raw strings + exact
`$N` numbering"; handler line corrected to `:328`. No remaining contradictions.

## Validation Log

### Session 1 — 2026-06-30 (4 questions)
Verification pass skipped — `## Red Team Review` already carries `file:line` evidence; no
`[UNVERIFIED]` tags remained.

| Topic | Decision | Effect |
|-------|----------|--------|
| NULL-tier UX (finding 6) | FE hint only; exclude NULL on tier filter | Confirmed plan as-is |
| Tier index (finding 5) | Bundle `CREATE INDEX` in the single `0019` migration; accept brief boot lock (benchmark scale) | Phase 1 reverted to one migration |
| Query builder (finding 3) | Hand-edit both COUNT+SELECT strings with exact `$N` numbering | Confirmed plan as-is |
| Default time range (D1) | **Changed: last 1 hour** (was all-time) | Phase 3 default state + Phase 2 COUNT note |

### Whole-Plan Consistency Sweep
Re-read all files after propagation. D1 (all-time → last-1h) updated in plan.md, Phase 3
default filter state, and Phase 2 COUNT-cost note. Index decision reverted Phase 1 Step 1
to a single `0019` migration. No remaining contradictions across phases.

## Implementation Outcome (2026-06-30)

All four phases **done**. Diff kept surgical (16 files; 4 unrelated `cargo fmt`-only
files reverted).

- **P1/P2 (backend):** migration `0019` (nullable `tier` + index); `tier` on
  `SecurityEvent`/`CreateSecurityEvent`, single + batch inserts, `engine.rs`
  `log_security_event` literal (`AuditEvent` untouched); COUNT `$10/$11/$12` +
  SELECT `$10/$11/$12`+`LIMIT $13 OFFSET $14` with reordered binds; empty-tier→no-filter.
- **P3 (FE):** `tier` on TS type; tier multi-select + range picker + 1h/6h/24h/7d
  presets (default last-1h); NULL-tier hint; tier column; page resets to 1 on filter change.
- **P4:** decision `0011`, story `US-1207`, `/api/security-events` 401 guard.
- **Proof:** tier pinning test · storage filters incl. batch-path persistence (4) ·
  existing security_events (3) · broadcast/migrate (3) · attack_logs (5) · engine
  batch-writer (4) · JWT incl. new guard (6) · stats_logs (8) · event_detail (3) ·
  `tsc` + vite build · clippy clean.
- **Review:** DONE_WITH_CONCERNS → the one must-fix MEDIUM (FE page-reset on
  direct tier/range change) fixed and re-verified; two nits no-action/documented.
- **Remaining:** manual end-to-end against a running stack (P4 step 5) — PENDING
  (needs full stack); automated coverage stands in. `harness-cli` absent → file+git proof.

## Open questions

- None blocking. (D1 resolved in validation: last-1h default.) Implementation-time
  reviewer questions below were all resolved: empty `tier=` → normalized to `None`
  (no-filter, tested); `ApiError::Storage` → 500 with `StorageError` Display (Postgres
  driver message, not parameterized SQL/user input); batch path proven via test.
- Verify at implementation time (raised by reviewers, do not block planning): whether
  axum yields `Some("")` vs `None` for empty `tier=`; whether `ApiError` serializes raw
  SQL; current `security_events` row count (sizes the index-lock risk); whether the batch
  writer is always configured in the target deploy.
