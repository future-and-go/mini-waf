# Red Team — FR-030 Dashboard Backend

Date: 2026-05-15
Full adversarial review: `reports/red-team-260515-1720-plan-review.md` (8 critical + 8 important, all fixed).

This document captures the runtime adversarial scenarios the implementation must defend against. Plan-level findings are tracked separately in the full review.

## Adversarial Scenarios

| # | Scenario | Mitigation | Verified in phase |
|---|----------|-----------|-------------------|
| 1 | Cardinality explosion: 1M+ distinct paths in `security_events` | Top-20 LIMIT inside ranking CTE; pre-filter by time window before GROUP BY | Phase 2 (SQL CTE), Phase 4 (load test if needed) |
| 2 | Path strings >50KB (RFC 7230 allows large URIs) | `LEFT(path, 256)` in SELECT projection caps payload row size; FE truncates display | Phase 2 |
| 3 | SQL injection via `host_code`/`action` query params | All queries use `sqlx::query(...).bind()` parameterized binds; no string interpolation | Phase 2 + 3 |
| 4 | `hours=999999` DoS (huge window scan) | Clamp `1..=720` server-side via `clamp_hours()` helper; bind `i32::try_from()` truncation as second defense | Phase 3 |
| 5 | Auth bypass on new endpoint | Route registered inside JWT-protected `Router` block in `server.rs:155-157` (mirrors `stats_overview`). Pre-edit + post-edit grep asserts placement | Phase 3 step 4 |
| 6 | NULL `rule_id` events crash category derivation | `category_of(NULL)` returns `'other'` via SQL `ELSE` branch — function signature `(TEXT) RETURNS TEXT`, NULL-safe | Phase 2 + Phase 4 test #1 |
| 7 | Empty `security_events` table at install time | Heatmap returns `{cells: [], total_events: 0, paths_sampled: 0, categories_total: 0}` — no panic, no division by zero | Phase 4 test |
| 8 | Refactor regression: `/api/stats/overview` shape drifts | Dedicated `stats_overview_backward_compat.rs` snapshot test asserts `serde_json::Value` deep equality with pre-refactor capture | Phase 4 step 5 |
| 9 | Migration rollback needed mid-deploy | `CREATE OR REPLACE FUNCTION` is idempotent; rollback = `DROP FUNCTION IF EXISTS category_of(TEXT)`; documented in migration header | Phase 2 step 1 |
| 10 | Concurrent migration on multi-node deploy | sqlx migrations are sequential + idempotent (existing pattern); function CREATE OR REPLACE is concurrent-safe | Phase 2 (no extra work) |
| 11 | Coverage tool drift between dev and CI | Both use `cargo-llvm-cov` (researcher 1 §Q11); CI floors raised atomically with new code | Phase 4 + 5 |
| 12 | Empty-string query param `host_code=""` treated as filter (matches nothing) | `empty_string_as_none` deserializer maps `""` → `None` before binding | Phase 3 step 1 |
| 13 | LIKE-clause SQL injection via `rule_id` prefix (defensive — input is internal) | `category_of()` body is fixed CASE expression; no user input flows into LIKE patterns | Phase 2 |
| 14 | Timezone mismatch: `created_at` interpreted as local time | Column is `TIMESTAMPTZ`; `NOW()` returns `timestamptz`; subtraction tz-safe | Phase 2 §risk |
| 15 | Auth token leakage via long-running heatmap query | Query targets p99 ≤5ms via index `security_events(created_at)` (existing); no long-lived txns | Phase 2 §non-functional |
| 16 | `category_of()` returns string different from existing inline CASE (silent FE chart break) | Migration copies branches VERBATIM from `repo.rs:990-1019`; tests cover ALL 30 branches + ordering (e.g. `CRS-RESP` must match BEFORE `CRS-`) | Phase 2 step 1, Phase 4 tests |

## Out-of-scope (acknowledged risk, not fixed this PR)

- Materialized view for heatmap (researcher 2 §Q3 deferred) — only relevant if live query proves slow at production scale post-deploy.
- Per-new-line coverage CI gate (F8 stretch) — crate-floor ratchet is MVP enforcement; jq-diff implementation deferred.
- Heatmap by `Path × Time-bucket` (alternate dimension) — out of scope; current plan covers `Path × Category` only.

## Gate Decision

All scenarios mapped to a verifying phase. **GO** for phase 2.
