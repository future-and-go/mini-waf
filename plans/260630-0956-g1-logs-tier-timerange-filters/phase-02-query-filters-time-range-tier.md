---
phase: 2
title: "Extend SecurityEventQuery — time-range + tier (read path)"
status: done
priority: P1
dependencies: [1]
---

# Phase 2: Extend SecurityEventQuery — time-range + tier (read path)

## Overview
Add `created_at_from`, `created_at_to`, and `tier` filter fields to
`SecurityEventQuery` and wire them into the query builder, reusing the existing
`($N IS NULL OR <cond>)` optional-filter pattern.

## Requirements
- Functional: `GET /api/security-events` accepts `created_at_from`, `created_at_to`
  (RFC3339), and `tier` (comma-joined). Each filter is optional and composes with the
  existing filters (host_code, client_ip, rule_name, action, path, country, …).
- Non-functional: filters apply identically to the COUNT and SELECT queries so `total`
  stays consistent; `page_size.clamp(1,100)` and `ORDER BY created_at DESC` unchanged.

## Architecture
`SecurityEventQuery` (`models.rs:322`) is deserialized straight from the query string by
axum `Query<SecurityEventQuery>` (`handlers.rs:328`) — adding fields needs no handler
change. The builder at `repo.rs:1853` is **two independent hand-written raw-SQL strings**
(COUNT at ~:1864-1886, SELECT at ~:1888-1914) — there is **no shared WHERE fragment**
variable. "Build once, reuse" is not literally possible without a refactor; either (a)
extract a shared `WHERE`-builder used by both (preferred — kills the drift class), or
(b) hand-edit both strings with the **exact** numbering below.

New predicates (each `$N` referenced twice is fine — Postgres allows positional reuse):
- `($N::timestamptz IS NULL OR created_at >= $N)`  — from
- `($M::timestamptz IS NULL OR created_at <= $M)`  — to
- `($K::text IS NULL OR tier = ANY(string_to_array($K, ',')))`  — tier multi (D2)

**Exact param numbering (finding 3 — the SELECT already ends `LIMIT $10 OFFSET $11`):**
- **COUNT** (no LIMIT/OFFSET): existing WHERE ends at `$9`; append from/to/tier as
  `$10` / `$11` / `$12`; append the three binds after the existing 9.
- **SELECT**: insert from/to/tier into the WHERE as `$10` / `$11` / `$12`, then **renumber
  `LIMIT` → `$13`, `OFFSET` → `$14`**, and **reorder the bind chain** so from/to/tier are
  bound *before* `page_size`/`offset`. (Naively appending as `$10/$11/$12` collides with
  the existing `LIMIT $10 OFFSET $11` → values bound into LIMIT → bigint cast error or
  broken pagination.)

Tier filter excludes `NULL`-tier (pre-migration) rows — see Phase 4 finding 6 for the
required behavior decision + FE hint. `created_at` is already indexed DESC; `tier` index
added in Phase 1.

## Related Code Files
- Modify:
  - `crates/waf-storage/src/models.rs` (~:322) — add to `SecurityEventQuery`:
    `created_at_from: Option<DateTime<Utc>>`, `created_at_to: Option<DateTime<Utc>>`,
    `tier: Option<String>`. (chrono `DateTime<Utc>` already used in this module.)
  - `crates/waf-storage/src/repo.rs` (~:1853) — add the three WHERE clauses + bindings
    to BOTH the COUNT and SELECT statements; keep `$N` numbering consistent.
- Create: `crates/waf-storage/tests/repo_security_events_filters.rs` (or extend the
  existing `repo_security_events.rs`).

## Implementation Steps
1. Add the three fields to `SecurityEventQuery` (all `Option`, default `None`):
   `created_at_from: Option<DateTime<Utc>>`, `created_at_to: Option<DateTime<Utc>>`,
   `tier: Option<String>`. (`chrono` has the `serde` feature — `Cargo.toml:54` — so axum
   `Query<>` deserializes RFC3339 into `DateTime<Utc>` out of the box.)
2. Normalize empty tier to `None` (fold-in, finding 9): if `tier` arrives as `Some("")`
   (cleared multiselect), treat as no filter — otherwise the `$K::text IS NULL` guard is
   false and `tier = ANY(string_to_array('', ','))` returns zero rows silently. Do this in
   the handler/builder (and have the FE omit the param — Phase 3).
3. Extend **both** raw SQL strings with the three predicates using the exact numbering in
   Architecture (COUNT `$10/$11/$12`; SELECT `$10/$11/$12` + `LIMIT $13 OFFSET $14`,
   binds reordered). Prefer extracting a shared WHERE-builder to avoid hand-editing two
   strings.
4. **Timestamp contract (fold-in, finding 13):** the FE MUST send `Z`-suffixed RFC3339
   (`toISOString()`). A `+00:00` offset is URL-decoded with `+`→space by
   `serde_urlencoded`, failing to parse and 400-ing the whole request. Document this as a
   hard contract requirement; add a test that a malformed timestamp degrades predictably.
5. Add tests (see below).

## Success Criteria
- [ ] Time window narrows results to `[from, to]` inclusive; omitting both returns all.
- [ ] `tier=Critical,High` returns only those tiers; NULL-tier rows excluded;
      `tier=` (empty) behaves as no filter (not zero-rows).
- [ ] Filters compose with existing ones **and with pagination across >1 page**; `total`
      matches the filtered set, not the table (catches COUNT/SELECT predicate or `$N`
      desync).
- [ ] A `Z`-suffixed timestamp filters correctly; a malformed one degrades predictably
      (documented behavior, not a 500).
- [ ] `cargo test -p waf-storage` green.

## Risk Assessment
- **`$N`/LIMIT collision (finding 3):** appending WHERE params as `$10/$11/$12` collides
  with the SELECT's existing `LIMIT $10 OFFSET $11`. Mitigation: exact numbering in
  Architecture; pagination-with-filter test.
- **COUNT/SELECT divergence:** no shared fragment exists today (two raw strings).
  Mitigation: extract a shared builder, or test `total` == returned count at a fixture
  size exceeding one page.
- **COUNT cost (fold-in, finding 11):** `COUNT(*)` runs over the full filtered set per
  list call. The last-1h default range (D1, validation session 1) bounds the common-case
  scan; only an explicit wide range hits O(rows). Acceptable at benchmark scale;
  re-evaluate (statement_timeout / approximate count) before large-scale use.
- **Timestamp parsing:** mismatched tz/format yields empty results or 400. Mitigation:
  `Z`-only contract (Step 4); explicit test.
