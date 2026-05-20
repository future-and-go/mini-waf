---
phase: 1
title: Brainstorm-RedTeam-Validate
status: completed
effort: 1h
priority: P1
---

# Phase 1: Brainstorm — Red Team — Validate

## Context Links

- `analysis/requirements.md:69-72` — FR-030 spec.
- `rules.md` #4 — mandatory gate before implementation.
- Research: `research/researcher-heatmap-data-model.md` (10 Q&A already cover most variants).
- Research: `research/researcher-existing-stats-backend.md` (existing schema/handlers).

## Overview

Mandatory gate (per `rules.md` #4): brainstorm alternatives, red-team adversarial scenarios, validate critical assumptions before any code. Reuse research output (already exhaustive) and lock decisions into two short reports.

**Deliverables:** `reports/brainstorm.md` + `reports/redteam.md` + 3-5 validation gate questions answered.

## Key Insights (locked from research)

- Sparse-cell JSON shape chosen (researcher 2 §Q2) — frontend-friendly, ~6-8KB gzipped.
- Top-20 paths by total event count (researcher 2 §Q3) — caps response at 240 cells worst case.
- Postgres IMMUTABLE function for `category_of(rule_id)` (researcher 2 §Q5) — kills 2x existing duplication, prevents 3rd.
- Existing indexes sufficient (researcher 2 §Q8) — no new index migration.
- Backward compat: `/api/stats/overview` with no params MUST yield current shape.

## Requirements

### Functional

- Produce `brainstorm.md` listing ≥3 alternative designs per axis (path normalization, response shape, DRY strategy) with chosen option highlighted.
- Produce `redteam.md` listing adversarial scenarios + mitigations.
- Validation: 5 critical questions answered IN WRITING; phase 2 blocked until all answered.

### Non-Functional

- Reports terse (markdown, sacrifice grammar for concision).
- Reports MUST cite research file paths.

## Architecture

No code. Decision recording only. Reports kept in `plans/260515-1714-fr030-dashboard-backend/reports/`.

## Related Code Files

**Read only (no modifications):**
- `plans/260515-1714-fr030-dashboard-backend/research/researcher-heatmap-data-model.md`
- `plans/260515-1714-fr030-dashboard-backend/research/researcher-existing-stats-backend.md`
- `crates/waf-storage/src/repo.rs` (lines 882-1250) — verify duplication count.

**Create:**
- `plans/260515-1714-fr030-dashboard-backend/reports/brainstorm.md`
- `plans/260515-1714-fr030-dashboard-backend/reports/redteam.md`

## Implementation Steps

### Step 1 — Brainstorm (≥3 alternatives per axis)

In `reports/brainstorm.md`, document for each axis the alternatives considered + chosen + rationale (1-3 lines each):

1. **Path normalization** (researcher 2 §Q1):
   - (a) raw paths + top-N — **CHOSEN**
   - (b) regex normalize-on-read — rejected (perf)
   - (c) `path_pattern` column + migration — rejected (YAGNI)
   - (d) SQL regex GROUP BY — rejected (cost = b)
2. **Response shape** (§Q2):
   - (a) dense matrix — rejected (waste, padding)
   - (b) sparse cells — **CHOSEN**
   - (c) path-grouped nested — rejected (FE re-pivot)
3. **Top-N selection** (§Q3):
   - (a) total event count — **CHOSEN**
   - (b) distinct rule count — rejected (niche)
   - (c) recency-weighted — rejected (complex)
4. **Category DRY strategy** (§Q5):
   - (a) Postgres IMMUTABLE function — **CHOSEN**
   - (b) Rust const SQL string — rejected (fragile)
   - (c) keep duplication — rejected (3x crosses line)
5. **Filter scope on `/api/stats/overview`**:
   - (a) host_code only — rejected (insufficient)
   - (b) host_code + action + hours — **CHOSEN**
   - (c) host_code + action + hours + path — rejected (YAGNI)

### Step 2 — Red Team (adversarial scenarios)

In `reports/redteam.md`, list each scenario + mitigation. Minimum coverage:

| # | Scenario | Mitigation |
|---|----------|-----------|
| 1 | Cardinality explosion (1M paths) | Top-20 LIMIT in CTE pre-filter (researcher 2 §Q3) |
| 2 | Long path strings (50KB) | `text` column unbounded; FE truncates display |
| 3 | Path injection / SQL injection | All queries parameterized via `sqlx::query(...).bind()` (researcher 1 §Q4) |
| 4 | `hours=999999` DoS | Clamp `1..=720` server-side in handler (researcher 1 §Q8) |
| 5 | Auth bypass on new endpoint | Route MUST sit under JWT-protected branch in `server.rs` (mirror `stats_overview`) |
| 6 | NULL `rule_id` rows | `category_of(NULL)` returns `'other'` via ELSE branch |
| 7 | Empty `security_events` table | Returns `{cells: [], total_events: 0}` (§Q9) |
| 8 | Refactor regression on `/api/stats/overview` shape | Test in phase 4 asserts shape byte-equivalence with empty filters |
| 9 | Migration rollback | New function is additive; `DROP FUNCTION IF EXISTS category_of(TEXT)` in rollback note |
| 10 | Concurrent migration on multi-node deploy | sqlx migrations are sequential + idempotent (existing pattern) |
| 11 | Coverage tool drift | Use `cargo-llvm-cov` (per researcher 1 §Q11) — same as CI |

### Step 3 — Validation Gate (5 questions, answer in writing)

Append to `reports/brainstorm.md` a **Validation Gate** section. Each Q must be answered Y/N + 1-line justification:

1. **Sparse JSON shape locked?** — Y, researcher 2 §Q2; frontend renders directly.
2. **New migration `0009_category_function.sql` acceptable?** — Y, additive, no schema change to existing tables.
3. **Docker-based test pattern unchanged?** — Y. `start_postgres()` at `crates/waf-storage/tests/common/mod.rs:33-46` spins its own `postgres:16-alpine` testcontainer per test file (verified via grep: every `tests/repo_*.rs` calls `start_postgres().await`). The `postgres` service block in `.github/workflows/coverage.yml:22-35` is incidental — testcontainers do NOT use it. Required: CI runner needs `/var/run/docker.sock` mounted; GitHub Ubuntu runners have it by default.
4. **Backward compat strategy for `/api/stats/overview`?** — Y, all new query params `Option<T>`; `None` = current behavior.
5. **Coverage target ≥90% applies to which files exactly?** — A: `repo.rs::get_endpoint_heatmap`, `repo.rs::category_of` invocations, refactored `get_stats_overview()` filter branches, `stats.rs::stats_endpoints`, refactored `stats.rs::stats_overview` query-param parsing.

If ANY answer is N or ambiguous → STOP and escalate before phase 2.

## Todo List

- [ ] Create `reports/brainstorm.md` with 5 axes × ≥3 alternatives.
- [ ] Create `reports/redteam.md` with ≥10 scenarios + mitigations.
- [ ] Append validation gate (5 Qs) to `brainstorm.md`.
- [ ] Confirm all 5 gate questions answered Y.

## Success Criteria

- [ ] `reports/brainstorm.md` exists, ≥50 LOC.
- [ ] `reports/redteam.md` exists, ≥30 LOC, ≥10 rows in table.
- [ ] Validation gate: 5/5 questions answered.
- [ ] No new code touched. Phase 2 unblocked.

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Skipped gate → wrong design baked in | Low | High | Gate is checklist; cannot start phase 2 without report files present |
| Research drift (research stale) | Low | Med | Re-verify line numbers in `repo.rs` against current HEAD before phase 2 |

## Security Considerations

None (no code). Phase 1 records security mitigations to enforce in phase 2-3.

## Next Steps

Phase 2 (storage layer) reads both reports as authority. Any design changes after gate require new gate iteration.
