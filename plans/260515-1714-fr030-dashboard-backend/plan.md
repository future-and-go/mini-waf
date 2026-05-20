---
title: FR-030 Dashboard Backend — Endpoint Heatmap + Enriched Stats
description: >-
  Add GET /api/stats/endpoints heatmap + filter params on /api/stats/overview,
  DRY category logic via Postgres function.
status: pending
priority: P1
effort: 10h
branch: feat/fr-030-dashboard-backend
tags:
  - waf-api
  - waf-storage
  - stats
  - dashboard
  - migration
created: 2026-05-15T00:00:00.000Z
---

# FR-030 Dashboard Backend — Endpoint Heatmap + Enriched Stats

## Red-Team Fixes Applied (2026-05-15 17:36)

Initial-plan verdict: **NO_GO** (8 critical + 8 important). Full report:
`reports/red-team-260515-1720-plan-review.md`. Fixes incorporated:

| # | Finding | Where fixed |
|---|---------|-------------|
| F1 | Fabricated category list (underscores, missing OWASP-942/941/930/931/932/933/913, ADV-SSRF/SSTI, CRS-RESP, API-MASS, MODSEC-RESP longer-prefix branches) | phase-02 §step 1: copy verbatim from `repo.rs:990-1019`; longer prefixes BEFORE shorter |
| F2 | `($1 \|\| ' hours')::INTERVAL` doesn't compile for bigint | phase-02 §step 3+4: use `make_interval(hours => $1::int)`; bind `i32::try_from(hours).unwrap_or(i32::MAX)` (pattern at `repo.rs:1161,1166`) |
| F3 | Tail categories DROPPED instead of rolled into `'other'` | phase-02 §step 3: SQL UNIONs tail-sum into `'other'`; `total_events` == sum of cells |
| F4 | `host_code=""` binds as `Some("")` (matches nothing) | phase-03 §step 1: `empty_string_as_none` custom deserializer on `Option<String>` |
| F5 | `attack_logs` vs `security_events` split unaddressed | phase-02 §step 4: per-subquery table-and-column matrix; filter no-ops when column absent |
| F7 | Test infra: confirmed `start_postgres()` IS testcontainers (`tests/common/mod.rs:33-46`); CI service is incidental | phase-01 Q3 reaffirmed; phase-04 unchanged but docker-socket requirement explicit |
| F8 | "90% on new code" had no CI gate | phase-04 §step 7 + phase-05 §step 1: raise crate floors (waf-storage 82→84, waf-api 78→80); stretch: jq diff of `--json` output |
| I3 | `LANGUAGE plpgsql IMMUTABLE` does NOT inline (only `LANGUAGE SQL` does) | phase-02 §step 1: function uses pure CASE body → `LANGUAGE SQL IMMUTABLE` |
| I4 | Backward-compat assertion was structural only | phase-04 §step 5: dedicated `stats_overview_backward_compat.rs` with deep `serde_json::Value` field check |
| I5 | Auth placement unspecified | phase-03 §step 4: route inside JWT-protected `Router` block (mirror `server.rs:155-157`) |
| I7 | Long path payload bloat | phase-02 §step 3: `LEFT(path, 256)` in SELECT to cap response |
| I8 | Timezone confirmation | phase-02 §risk: `TIMESTAMPTZ` + `NOW()` is tz-safe |

## Overview

Backend support for dashboard heatmap (FR-030, `analysis/requirements.md:69-72`).

Three deliverables:
1. **New endpoint** `GET /api/stats/endpoints` — Path × Attack-Category heatmap (sparse cells, with `'other'` rollup).
2. **Enriched** `GET /api/stats/overview` — optional `host_code`, `action`, `hours` filters (backward-compatible: empty query = current behavior).
3. **DRY refactor** — extract 30-branch CASE for `rule_id → category` to Postgres `LANGUAGE SQL IMMUTABLE` function `category_of(rule_id)` (new migration `0009_category_function.sql`). Replace 2 inline duplicates in `get_stats_overview()` + use in new heatmap query.

Coverage target: **≥90% on new code**. CI green. PR squashed to 1 commit.

## Phases

| Phase | Name | Status | Effort |
|-------|------|--------|--------|
| 1 | [Brainstorm-RedTeam-Validate](./phase-01-brainstorm-redteam-validate.md) | Pending | Completed |
| 2 | [Storage-Layer](./phase-02-storage-layer.md) | Pending | Completed |
| 3 | [API-Layer](./phase-03-api-layer.md) | Pending | Completed |
| 4 | [Tests-90pct](./phase-04-tests-90pct.md) | Pending | Completed |
| 5 | [PR-CI-Hardening](./phase-05-pr-ci-hardening.md) | Pending | In Progress |

## Dependencies

- Phase 2 blocks 3 (handler imports repo types).
- Phase 3 blocks 4 (integration tests need running handler).
- Phase 4 blocks 5 (CI requires green tests + coverage).
- No external blockers; existing indexes sufficient (researcher 2 §Q8).

## Research References

- `research/researcher-existing-stats-backend.md` — schema, code patterns, test infra, coverage tooling.
- `research/researcher-heatmap-data-model.md` — 10-question design rationale + final API contract + SQL skeleton.
- `analysis/requirements.md:69-72` — FR-030 spec.

## Success Metric

FR-030 backend complete: new heatmap endpoint live, overview filters threaded, ≥90% line coverage on new code, PR merged to `main` with CI green, no `.unwrap()` regression, `cargo fmt --check` clean.
