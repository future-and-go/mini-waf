---
phase: 1
title: "Persist tier to security_events (write path + schema)"
status: done
priority: P1
dependencies: []
---

# Phase 1: Persist tier to security_events (write path + schema)

## Overview
Add a `tier` column to the `security_events` table and populate it from the
per-request `ctx.tier` at insert time, so the filter in Phase 2 has data to query.
Forward-only: pre-existing rows stay `NULL`.

## Requirements
- Functional: every newly written security event records its protection tier
  (`Critical | High | Medium | CatchAll`) matching the JSONL audit value exactly.
- Non-functional: no change to the hot path's fire-and-forget logging behavior; no
  backfill of historical rows.

## Architecture
`ctx.tier` (type `waf_common::Tier`, `crates/waf-common/src/tier.rs:16`) is reachable in
`fn log_security_event` (`engine.rs:989`, signature `ctx: &RequestCtx, …`) but is **NOT
currently written** to the Postgres event — the `CreateSecurityEvent` literal at
`engine.rs:989-1008` ends at `waf_mode` with no tier field. The `tier:` line that already
exists at `engine.rs:1065` belongs to a **different function** (`send_audit_event`) and a
**different struct** (`AuditEvent`, the JSONL sink). Do **not** edit that one — it is
already correct. This phase adds a brand-new `tier` field to `CreateSecurityEvent` and a
new line in the `:989` literal, reusing the same Debug expression for D3 consistency.

**Runtime write path (critical):** `log_security_event` prefers the batch writer
(`engine.rs:1010-1011`: `if let Some(writer) = self.db_batch_writer.get() { writer.try_send(…) }`);
the single `create_security_event` (`repo.rs:427`) is only the **fallback** when no batch
writer is configured. In production the batch writer is active, so **100% of events flow
through `create_security_event_batch` (`repo.rs:486-511`)** — a separate hand-written
`QueryBuilder` with its own column list + `push_bind` chain that does NOT share SQL with
the single insert. If the batch column/bind list desyncs, `do_flush` catches the error and
**silently drops the whole batch** (`db_batch_writer.rs:100-101`) — every event lost, with
tests still green. The batch path is the primary edit target, not an afterthought.

## Related Code Files
There are **three** `INSERT INTO security_events` statements plus **two** non-SQL
struct-construction sites — all must be touched. (Line numbers drift; re-confirm at edit time.)
- Create:
  - `migrations/0019_security_events_tier.sql` — `ADD COLUMN tier TEXT` + `CREATE INDEX`
    (both in one migration; see Step 1).
- Modify (SQL / production write path):
  - `crates/waf-storage/src/models.rs` — add `tier: Option<String>` to `SecurityEvent`
    (~:106) and `CreateSecurityEvent` (~:308).
  - `crates/waf-storage/src/repo.rs` **(single insert, fallback)** — add `tier` to the
    `create_security_event` `INSERT` column list + `.bind()` (~:427).
  - `crates/waf-storage/src/repo.rs` **(batch insert, PRIMARY prod path)** — add `tier`
    to the `create_security_event_batch` `QueryBuilder` column list AND its `push_bind`
    chain (~:492-505). Column count must equal bind count.
- Modify (struct construction — no SQL, just literals that must set/compile the field):
  - `crates/waf-engine/src/engine.rs:989` — add `tier: Some(format!("{:?}", ctx.tier)),`
    to the `CreateSecurityEvent` literal in `log_security_event`. (NOT the `:1065`
    `AuditEvent` literal — that is a different struct/function, already correct.)
  - `crates/waf-engine/src/logging/db_batch_writer.rs:116` **and** `:206` — these are
    **test** `CreateSecurityEvent` literals; add `tier` so they compile. (db_batch_writer
    forwards the struct; it has no INSERT SQL of its own.)
- Modify (test fixtures — must compile with the new field; struct literals have no
  `..Default`, so the compiler flags each):
  - `crates/waf-api/tests/common/mod.rs`, `crates/waf-api/tests/handler_*.rs`,
    `crates/waf-storage/tests/repo_*.rs`,
    `crates/waf-storage/tests/db_migrate_and_broadcast.rs`.
  - `crates/waf-storage/tests/common/mod.rs:68` — a **hand-written** `INSERT INTO
    security_events` test helper with no column list entry for tier (omitting it is OK —
    nullable — but seeded rows then have NULL tier; relevant to Phase 2 tier-filter tests).

## Implementation Steps
1. Migrations run **automatically at server boot** (`crates/prx-waf/src/main.rs:1553` →
   `db.migrate()`), inside sqlx's transactional runner. <!-- Updated: Validation Session 1
   - index bundled in single 0019 migration; accept brief boot lock at benchmark scale -->
   `0019_security_events_tier.sql` contains BOTH:
   - `ALTER TABLE security_events ADD COLUMN tier TEXT;` (fast metadata-only op on PG 11+).
   - `CREATE INDEX idx_security_events_tier ON security_events (tier);`
   A plain (non-concurrent) `CREATE INDEX` takes a write-blocking lock for the build
   duration; `CONCURRENTLY` can't run in the migration transaction. Accepted here because
   the deployment is benchmark/dev-scale (small table). Re-evaluate (split out + build
   `CONCURRENTLY` via a maintenance task) before any large-table deploy — confirm
   `security_events` row count first. See Risk below.
2. Add `pub tier: Option<String>` to `SecurityEvent` and `CreateSecurityEvent` (models.rs).
3. Update **both** INSERTs in `repo.rs`: `create_security_event` single insert (~:427,
   column + `$N` + bind) AND `create_security_event_batch` (~:492-505, QueryBuilder column
   list + `push_bind`). Keep column-count == bind-count in the batch path.
4. Add `tier: Some(format!("{:?}", ctx.tier)),` to the `CreateSecurityEvent` literal in
   `log_security_event` (`engine.rs:989`). Do not touch the `:1065` `AuditEvent` literal.
5. Add `tier` to the two test `CreateSecurityEvent` literals in `db_batch_writer.rs`
   (:116, :206).
6. Add a `tier` value to every other `CreateSecurityEvent` fixture so the workspace
   compiles (let the compiler enumerate them).
7. Pin the format contract (fold-in, finding 8): add a unit test asserting
   `format!("{:?}", Tier::CatchAll) == "CatchAll"` (and the other three variants) so a
   future switch to serde serialization — which would emit `catch_all` per
   `tier.rs` `rename_all="snake_case"` — breaks the build instead of silently
   mismatching the FE filter strings.

## Success Criteria
- [ ] `cargo build -p waf-storage -p waf-engine -p waf-api` green.
- [ ] Migration(s) apply cleanly on a fresh DB; column + index present.
- [ ] Events pushed through the **batch writer** path (`DbBatchWriter`, the production
      path) persist a non-null `tier` — assert via `SELECT count(*) FROM security_events
      WHERE tier IS NULL AND created_at > <test_start>` = 0. (Single-insert-only tests do
      not prove the prod path.)
- [ ] Persisted `tier` matches the JSONL audit `tier` for the same request
      (`Critical|High|Medium|CatchAll`).
- [ ] Format-pinning test (Step 7) passes.
- [ ] Existing `repo`/`handler` tests pass with the new field.

## Risk Assessment
- **Wrong edit target (finding 1):** the `tier:` at `engine.rs:1065` is `AuditEvent`, not
  `CreateSecurityEvent`. Editing it instead of `:989` ships NULL tier silently.
  Mitigation: edit-time confirm the literal you touch is inside `log_security_event` and
  ends at `waf_mode`.
- **Batch path drop (finding 2):** the batch insert (`repo.rs:492-505`) is the prod path;
  a column/bind mismatch makes `do_flush` drop the whole batch silently
  (`db_batch_writer.rs:100`). Mitigation: keep column-count == bind-count; success
  criterion exercises the batch path specifically.
- **Index boot-lock (finding 5):** non-concurrent `CREATE INDEX` at startup blocks
  `security_events` writes; `CONCURRENTLY` can't run in the migration tx. Mitigation:
  accepted at current (benchmark) scale (validation session 1); re-evaluate (split out +
  `CONCURRENTLY`) before any large-table deploy.
- **Struct-field blast radius:** adding a field to `CreateSecurityEvent` breaks every
  constructor. Mitigation: rely on the compiler (literals have no `..Default`).
- **Format drift (finding 8):** Debug (`CatchAll`) ≠ serde (`catch_all`); a serde switch
  silently breaks the FE filter equality. Mitigation: Step 7 pinning test; decision-record
  note (Phase 4) forbidding the serde switch without updating both sides.
- **Rollback:** column add is additive/nullable — safe; revert is `DROP COLUMN tier`.
