# Brainstorm — FR-030 Dashboard Backend

Date: 2026-05-15
References: `research/researcher-heatmap-data-model.md`, `research/researcher-existing-stats-backend.md`

## Design Alternatives (5 axes × ≥3 options)

### 1. Path normalization (researcher 2 §Q1)
- (a) **CHOSEN** — Raw paths + top-N LIMIT. Zero migration cost, KISS. Researcher 2 confirmed top-20 caps cardinality at sane bounds.
- (b) Regex normalize-on-read (`/api/v1/users/12345` → `/api/v1/users/:id`). Rejected — adds CPU per query, perf risk vs NFR (p99 ≤5ms).
- (c) Add `path_pattern` column at write time. Rejected — schema migration + write-path change, YAGNI.
- (d) SQL regex GROUP BY. Rejected — equivalent cost to (b).

### 2. Response shape (§Q2)
- (a) Dense matrix `{paths, categories, matrix[][]}`. Rejected — wastes bytes (0-padded cells), awkward to extend.
- (b) **CHOSEN** — Sparse cells `{cells: [{path, category, count}, ...]}`. Frontend-friendly for D3/visx, ~6-8KB gzip, easy to filter/sort.
- (c) Path-grouped nested `{endpoints: [{path, by_category: {...}}, ...]}`. Rejected — forces FE re-pivot for matrix layout.

### 3. Top-N selection strategy (§Q3)
- (a) **CHOSEN** — Total event count, pre-filtered to time window. Simplest, most-attacked endpoints surface first.
- (b) Distinct rule-id count (attack surface diversity). Rejected — niche metric, harder UX explanation.
- (c) Recency-weighted (decay function). Rejected — complex, premature optimization.

### 4. Category DRY strategy (§Q5)
- (a) **CHOSEN** — Postgres `LANGUAGE SQL IMMUTABLE` function `category_of(rule_id)`. Inlined by planner → zero overhead. Kills 2x existing duplication, blocks 3rd in heatmap query.
- (b) Rust const SQL fragment string. Rejected — fragile (string concat into queries), no DB-side type safety.
- (c) Keep duplication (accept 3x). Rejected — explicit DRY violation, error-prone when adding new prefix.

### 5. Filter scope on `/api/stats/overview`
- (a) `host_code` only. Rejected — insufficient for multi-tenant dashboard filtering.
- (b) **CHOSEN** — `host_code` + `action` + `hours`. Matches three pivot axes FE needs; `hours` reuses existing `timeseries` clamp semantics.
- (c) (b) + `path`/`rule_id`. Rejected — YAGNI; deep-drill belongs in `/api/security-events` list endpoint.

## Validation Gate

| # | Question | A |
|---|----------|---|
| 1 | Sparse JSON shape locked? | **Y** — researcher 2 §Q2; FE renders directly without re-pivot. |
| 2 | New migration `0009_category_function.sql` acceptable? | **Y** — additive (CREATE FUNCTION); no schema change to existing tables; idempotent via `CREATE OR REPLACE`. |
| 3 | Docker-based test pattern unchanged? | **Y** — `start_postgres()` testcontainer pattern at `crates/waf-storage/tests/common/mod.rs:33-46` already standard. CI Postgres service is incidental, NOT used by tests. Docker socket required (default on GitHub Ubuntu runners). |
| 4 | Backward compat strategy for `/api/stats/overview`? | **Y** — every new query param is `Option<T>`; `None` (empty query) = current behavior. Snapshot test `stats_overview_backward_compat.rs` enforces byte-equivalence. |
| 5 | Coverage target ≥90% applies to which files? | **A** — `repo.rs::get_endpoint_heatmap`, `repo.rs::category_of` invocations (post-refactor), `repo.rs::get_stats_overview` new filter branches, `stats.rs::stats_endpoints`, `stats.rs::stats_overview` query-param parsing, `empty_string_as_none` deserializer, `clamp_hours` helper. Enforced via crate-floor ratchet (waf-storage 82→84, waf-api 78→80). |

All Y. Phase 2 unblocked.

## Decisions Locked (do not revisit without new gate)

- Sparse cells JSON, top-20 paths, top-12 categories + `'other'` rollup, `make_interval(hours => $1::int)` SQL pattern, `LEFT(path, 256)` payload bound, `LANGUAGE SQL IMMUTABLE` function, JWT-protected route, crate-floor ratchet for coverage gate.
