---
phase: 2
title: Storage-Layer
status: completed
effort: 3h
priority: P1
depends_on:
  - 1
---

# Phase 2: Storage Layer — Migration + Repo + Models

## Context Links

- Research: `research/researcher-heatmap-data-model.md` §Q5, §Q6, §Q7 (function + SQL + filter signature).
- Research: `research/researcher-existing-stats-backend.md` §Q2 (existing duplication locations), §Q11 (coverage).
- Existing: `crates/waf-storage/src/repo.rs:882-1250` (current `get_stats_overview` with 2× inline CASE).
- Existing: `crates/waf-storage/src/models.rs:425-500` (existing stats shapes).
- Existing: `migrations/0008_add_geo_info_to_attack_logs.sql` (next migration is `0009_*`).

## Overview

Three storage-layer changes:

1. **Migration** `0009_category_function.sql` — Postgres IMMUTABLE function `category_of(rule_id TEXT) RETURNS TEXT` with all 28 CASE branches.
2. **DRY refactor** — Replace 2 inline CASEs in `get_stats_overview()` with `category_of(rule_id)`.
3. **New repo method** `get_endpoint_heatmap(filter: HeatmapFilter) -> Result<EndpointHeatmap, StorageError>` + extend `get_stats_overview` with optional `StatsFilter`.

## Key Insights

- Function is IMMUTABLE → planner inlines, zero overhead vs CASE (researcher 2 §Q5).
- Existing indexes (`idx_security_events_created_at`, `idx_security_events_host_code`, `idx_security_events_action`) cover all new query branches (researcher 2 §Q8).
- `get_stats_overview` has 8+ subqueries; each needs same WHERE-clause builder. Build helper to avoid 8× duplication.
- Backward compat: `StatsFilter::default()` (all `None`) MUST produce byte-equivalent rows to current `get_stats_overview()` output.

## Requirements

### Functional

- `category_of('SQLI-001')` = `'sqli'`; `category_of(NULL)` = `'other'`; covers all 30 branches matching the live CASE at `repo.rs:990-1019`.
- `get_endpoint_heatmap(filter)` returns sparse `Vec<HeatmapCell>` + metadata (total_events, paths_sampled, categories_total, window_hours, generated_at).
- `get_stats_overview(filter)` accepts `StatsFilter { hours: Option<i64>, host_code: Option<String>, action: Option<String> }`. `StatsFilter::default()` = current behavior.

### Non-Functional

- All queries parameterized (`.bind()`), no string interpolation of user input.
- No `.unwrap()` / `.expect()` in production code (Seven Iron Rules).
- `cargo check -p waf-storage` passes (Iron Rule #4).

## Architecture

### Data flow

```
HeatmapFilter ──▶ get_endpoint_heatmap()
                    │
                    ├─ Stage 1 CTE: rank top-20 paths by COUNT(*)
                    ├─ Stage 2 CTE: top-12 categories via category_of(rule_id)
                    └─ Stage 3: SELECT path, category_of(rule_id), COUNT(*)
                          (filtered to top paths + window + host_code + action)
                    │
                    ▼
              Vec<HeatmapCell> + metadata
```

```
StatsFilter ──▶ get_stats_overview()
                  │
                  └─ each subquery gets WHERE-clause built by
                     build_where_clause(&filter) helper
                  │
                  ▼
                StatsOverview (existing shape, unchanged)
```

## Related Code Files

**Create:**
- `migrations/0009_category_function.sql` — function definition.

**Modify:**
- `crates/waf-storage/src/models.rs` — add `HeatmapCell`, `EndpointHeatmap`, `HeatmapFilter`, `StatsFilter` structs.
- `crates/waf-storage/src/repo.rs` — add `get_endpoint_heatmap()`; refactor `get_stats_overview()` to accept `StatsFilter` and use `category_of()`.

**Delete:** none.

## Implementation Steps

### Step 1 — Migration (VERBATIM copy from `repo.rs:990-1019`)

**Critical (red-team F1):** the branch list below is copied byte-for-byte from the live source. DO NOT modify names, hyphens, or order. Longer prefixes (`OWASP-942`, `ADV-SSRF`, `CRS-RESP`, `API-MASS`, `MODSEC-RESP`) MUST appear BEFORE their shorter relatives (`OWASP-`, `ADV-`, `CRS-`, `API-`, `MODSEC-`) — Postgres `CASE WHEN` evaluates top-down; reordering silently breaks category assignment.

**Critical (red-team I3):** body is a pure expression → use `LANGUAGE SQL IMMUTABLE` so the planner can inline. `plpgsql` IMMUTABLE is NOT inlined.

**Pre-step grep verification (mandatory before writing migration):**
```bash
sed -n '990,1019p' crates/waf-storage/src/repo.rs > /tmp/case-live.txt
sed -n '1074,1103p' crates/waf-storage/src/repo.rs > /tmp/case-live-2.txt
diff /tmp/case-live.txt /tmp/case-live-2.txt
# diff MUST be empty — both inline CASEs in repo.rs are identical
```

Create `migrations/0009_category_function.sql`:

```sql
-- 0009_category_function.sql
-- Centralized category derivation for security_events.rule_id.
-- DRY: replaces inline CASE expressions duplicated at repo.rs:987-1027 and
-- repo.rs:1062-1108. The new endpoint heatmap (repo.rs::get_endpoint_heatmap)
-- is the 3rd consumer.
-- LANGUAGE SQL IMMUTABLE: planner inlines the CASE body into the calling
-- query, zero per-row function-call overhead.

CREATE OR REPLACE FUNCTION category_of(rule_id TEXT) RETURNS TEXT AS $$
  SELECT CASE
    WHEN rule_id LIKE 'SQLI-%'        THEN 'sqli'
    WHEN rule_id LIKE 'XSS-%'         THEN 'xss'
    WHEN rule_id LIKE 'RCE-%'         THEN 'rce'
    WHEN rule_id LIKE 'TRAV-%'        THEN 'path-traversal'
    WHEN rule_id LIKE 'SCAN-%'        THEN 'scanner'
    WHEN rule_id LIKE 'BOT-%'         THEN 'bot'
    WHEN rule_id LIKE 'CC-%'          THEN 'cc-ddos'
    WHEN rule_id LIKE 'ADV-SSRF%'     THEN 'ssrf'
    WHEN rule_id LIKE 'ADV-SSTI%'     THEN 'ssti'
    WHEN rule_id LIKE 'ADV-%'         THEN 'advanced'
    WHEN rule_id LIKE 'CRS-RESP%'     THEN 'data-leakage'
    WHEN rule_id LIKE 'CRS-%'         THEN 'owasp-crs'
    WHEN rule_id LIKE 'API-MASS%'     THEN 'mass-assignment'
    WHEN rule_id LIKE 'API-%'         THEN 'api-security'
    WHEN rule_id LIKE 'MODSEC-RESP%'  THEN 'web-shell'
    WHEN rule_id LIKE 'MODSEC-%'      THEN 'modsecurity'
    WHEN rule_id LIKE 'CVE-%'         THEN 'cve'
    WHEN rule_id LIKE 'GEO-%'         THEN 'geo-blocking'
    WHEN rule_id LIKE 'CUSTOM-%'      THEN 'custom'
    WHEN rule_id LIKE 'IP-%'          THEN 'ip-rule'
    WHEN rule_id LIKE 'URL-%'         THEN 'url-rule'
    WHEN rule_id LIKE 'SENS-%'        THEN 'sensitive-data'
    WHEN rule_id LIKE 'HOTLINK-%'     THEN 'anti-hotlink'
    WHEN rule_id LIKE 'OWASP-942%'    THEN 'sqli'
    WHEN rule_id LIKE 'OWASP-941%'    THEN 'xss'
    WHEN rule_id LIKE 'OWASP-930%'    THEN 'lfi'
    WHEN rule_id LIKE 'OWASP-931%'    THEN 'rfi'
    WHEN rule_id LIKE 'OWASP-932%'    THEN 'rce'
    WHEN rule_id LIKE 'OWASP-933%'    THEN 'php-injection'
    WHEN rule_id LIKE 'OWASP-913%'    THEN 'scanner'
    ELSE 'other'
  END;
$$ LANGUAGE SQL IMMUTABLE;
```

**Branch count: 30 WHEN clauses + ELSE.** Verify exact match with `repo.rs:990-1019`:
```bash
grep -c "WHEN rule_id LIKE" migrations/0009_category_function.sql   # expect 30
grep -c "WHEN rule_id LIKE" crates/waf-storage/src/repo.rs           # expect 60 (30×2)
```

**Rollback (NOT executed):**
```sql
DROP FUNCTION IF EXISTS category_of(TEXT);
```
Then revert the 2 refactor sites in `repo.rs` to inline CASE.

### Step 2 — Models

Append to `crates/waf-storage/src/models.rs`:

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeatmapCell {
    pub path: String,
    pub category: String,
    pub count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EndpointHeatmap {
    pub cells: Vec<HeatmapCell>,
    pub total_events: i64,
    pub paths_sampled: i64,
    pub categories_total: i64,
    pub window_hours: i64,
    pub generated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct HeatmapFilter {
    pub hours: i64,                  // clamped 1..=720 by caller
    pub host_code: Option<String>,
    pub action: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct StatsFilter {
    pub hours: Option<i64>,          // None = all-time (current behavior)
    pub host_code: Option<String>,
    pub action: Option<String>,
}
```

Re-export from `lib.rs` if existing models are re-exported (match existing pattern).

### Step 3 — `get_endpoint_heatmap` in `repo.rs`

Add method after `get_geo_stats` (end of stats block at `repo.rs:1269`).

**Fixes applied:**
- **F2:** `make_interval(hours => $1::int)` (proven pattern at `repo.rs:1161`); bind `i32::try_from(filter.hours).unwrap_or(i32::MAX)` (pattern at `repo.rs:1166`). The earlier `($1 || ' hours')::INTERVAL` does NOT compile for a bigint bind.
- **F3:** tail categories beyond top-12 roll into `'other'`. Two-stage: top-12 list selected first; then in the final SELECT, any category NOT in that list is bucketed `'other'`. `total_events` (metadata) == `SUM(count)` over returned cells.
- **I7:** `LEFT(path, 256)` caps payload size; clients render with ellipsis if needed.

```rust
pub async fn get_endpoint_heatmap(
    &self,
    filter: &HeatmapFilter,
) -> Result<EndpointHeatmap, StorageError> {
    use sqlx::Row;

    // Clamp hours to fit i32 for make_interval; caller already enforces 1..=720
    // but we defend in depth.
    let hours_i32 = i32::try_from(filter.hours).unwrap_or(i32::MAX);
    let host = filter.host_code.as_deref();
    let action = filter.action.as_deref();

    // 3-stage CTE:
    //   path_ranks    — top 20 paths by event count in window
    //   category_top  — top 12 categories in window
    //   final SELECT  — pivot path × (top-category OR 'other' rollup), sparse
    let rows = sqlx::query(
        r#"
        WITH path_ranks AS (
          SELECT LEFT(path, 256) AS path, COUNT(*)::bigint AS total_events
          FROM security_events
          WHERE created_at >= NOW() - make_interval(hours => $1::int)
            AND ($2::text IS NULL OR host_code = $2)
            AND ($3::text IS NULL OR action    = $3)
          GROUP BY LEFT(path, 256)
          ORDER BY total_events DESC
          LIMIT 20
        ),
        category_top AS (
          SELECT category_of(rule_id) AS category, COUNT(*)::bigint AS total
          FROM security_events
          WHERE created_at >= NOW() - make_interval(hours => $1::int)
            AND ($2::text IS NULL OR host_code = $2)
            AND ($3::text IS NULL OR action    = $3)
            AND rule_id IS NOT NULL
          GROUP BY category_of(rule_id)
          ORDER BY total DESC
          LIMIT 12
        )
        SELECT
          LEFT(se.path, 256) AS path,
          CASE
            WHEN category_of(se.rule_id) IN (SELECT category FROM category_top)
              THEN category_of(se.rule_id)
            ELSE 'other'
          END AS category,
          COUNT(*)::bigint AS count
        FROM security_events se
        WHERE LEFT(se.path, 256) IN (SELECT path FROM path_ranks)
          AND se.created_at >= NOW() - make_interval(hours => $1::int)
          AND ($2::text IS NULL OR se.host_code = $2)
          AND ($3::text IS NULL OR se.action    = $3)
          AND se.rule_id IS NOT NULL
        GROUP BY LEFT(se.path, 256),
                 CASE
                   WHEN category_of(se.rule_id) IN (SELECT category FROM category_top)
                     THEN category_of(se.rule_id)
                   ELSE 'other'
                 END
        ORDER BY path, count DESC;
        "#,
    )
    .bind(hours_i32)
    .bind(host)
    .bind(action)
    .fetch_all(&self.pool)
    .await?;

    let mut cells: Vec<HeatmapCell> = Vec::with_capacity(rows.len());
    let mut paths = std::collections::HashSet::<String>::new();
    let mut cats = std::collections::HashSet::<String>::new();
    let mut total: i64 = 0;

    for r in rows {
        let path: String = r.try_get("path")?;
        let category: String = r.try_get("category")?;
        let count: i64 = r.try_get("count")?;
        paths.insert(path.clone());
        cats.insert(category.clone());
        total = total.saturating_add(count);
        cells.push(HeatmapCell { path, category, count });
    }

    let paths_sampled = i64::try_from(paths.len()).unwrap_or(i64::MAX);
    let categories_total = i64::try_from(cats.len()).unwrap_or(i64::MAX);

    Ok(EndpointHeatmap {
        cells,
        total_events: total,
        paths_sampled,
        categories_total,
        window_hours: filter.hours,
        generated_at: Utc::now(),
    })
}
```

**Verification invariants (phase 4 asserts these):**
- `total_events == cells.iter().map(|c| c.count).sum()` for any non-empty result.
- If 13+ distinct categories present in window, exactly one cell category equals `"other"` per path (where tail-cat events exist).
- `paths_sampled <= 20`, `categories_total <= 13` (12 top + possibly `other`).

**Notes:**
- `make_interval(hours => $1::int)` matches existing pattern at `repo.rs:1161` — verified compiles in production.
- All path projections use `LEFT(path, 256)`; GROUP BY uses the same expression so grouping aligns with output.
- `try_get` propagates `?`; no `.unwrap()`. `i64::try_from` for HashSet sizes guards against impossible-but-checked overflow.
- Cardinality bounded: 20 paths × ≤13 categories = ≤260 rows worst case.

### Step 4 — Refactor `get_stats_overview` (DRY + filters)

**Fixes applied:**
- **F2:** every interval filter uses `make_interval(hours => $N::int)` with `i32::try_from(...)` bind.
- **F5:** explicit per-subquery table-and-column matrix. `get_stats_overview()` reads from THREE tables (`attack_logs`, `security_events`, `hosts`); not every filter applies to every subquery. Filter must be a no-op for tables that lack the column — NEVER reference a missing column or the query crashes.

Change signature:

```rust
// BEFORE (repo.rs:882)
pub async fn get_stats_overview(&self) -> Result<StatsOverview, StorageError>

// AFTER
pub async fn get_stats_overview(
    &self,
    filter: &StatsFilter,
) -> Result<StatsOverview, StorageError>
```

#### Per-subquery table+filter matrix

Auditing `repo.rs:882-1148` line-by-line. `host_code` and `action` columns confirmed present on both `attack_logs` (`migrations/0001_initial.sql:84-103`) and `security_events` (`migrations/0002_security_events.sql:1-21`). `hosts` table has neither (host_code IS the PK there). Filter applicability:

| # | Source line | Subquery | Table | hours filter | host_code filter | action filter |
|---|------------|----------|-------|--------------|------------------|---------------|
| 1 | `repo.rs:883` | `total_blocked_logs` | `attack_logs` | YES (`created_at`) | YES | hardcoded `action='block'` — UI filter `action=X` must REPLACE the hardcoded one ONLY when `X` is provided (else keep `'block'`); see note below |
| 2 | `repo.rs:887` | `total_blocked_events` | `security_events` | YES | YES | same — replace hardcoded `'block'` only if UI filter set |
| 3 | `repo.rs:892` | `total_allowed` | `attack_logs` | YES | YES | hardcoded `action='allow'` — if UI filter set to something ≠ `allow`, this subquery returns 0 (correct semantics: "allowed under this action filter" is nonsensical, return 0) |
| 4 | `repo.rs:898` | `hosts_count` | `hosts` | NO (no created_at) | NO (host_code IS pk) | NO | filters NO-OP for this subquery |
| 5 | `repo.rs:903` | `top_ips` | `security_events` | YES | YES | YES |
| 6 | `repo.rs:921` | `top_rules` | `security_events` | YES | YES | YES |
| 7 | `repo.rs:939` | `top_countries` | `security_events` | YES | YES | YES |
| 8 | `repo.rs:958` | `top_isp_list` | `security_events` | YES | YES | YES |
| 9 | `repo.rs:977` | `unique_attackers` | `security_events` | YES | YES | YES |
| 10 | `repo.rs:987` | `category_breakdown` | `security_events` | YES | YES | YES — also swap inline CASE for `category_of(rule_id)` |
| 11 | `repo.rs:1042` | `action_breakdown` | `security_events` | YES | YES | NO (would break the breakdown if applied — `action_breakdown` IS the chart that shows actions; filtering it by action would always return 1 row) |
| 12 | `repo.rs:1062` | `recent_events` | `security_events` | YES | YES | YES — also swap inline CASE for `category_of(rule_id)` |

**Hardcoded action subqueries (#1, #2, #3) — semantic decision:**
- If UI sets `filter.action = Some("block")` → subqueries #1, #2 keep `action='block'`, #3 returns 0.
- If UI sets `filter.action = Some("allow")` → #1, #2 return 0, #3 keeps `action='allow'`.
- If UI sets `filter.action = Some("log")` (or other) → all three count rows matching that action; `total_blocked` becomes "events matching this action under block-style accounting." Document this in the handler's docstring; phase 3 mirrors it.
- If `filter.action = None` (default / backward-compat) → behavior unchanged (current production behavior).

#### Filter pattern (template — apply per row in matrix)

```rust
// Example for subquery #5 (top_ips, all three filters apply):
let top_ips: Vec<TopEntry> = sqlx::query(
    r#"
    SELECT client_ip AS entry_key, COUNT(*)::bigint AS cnt
    FROM security_events
    WHERE ($1::int  IS NULL OR created_at >= NOW() - make_interval(hours => $1))
      AND ($2::text IS NULL OR host_code = $2)
      AND ($3::text IS NULL OR action    = $3)
    GROUP BY client_ip
    ORDER BY cnt DESC
    LIMIT 10
    "#,
)
.bind(filter.hours.map(|h| i32::try_from(h).unwrap_or(i32::MAX)))
.bind(filter.host_code.as_deref())
.bind(filter.action.as_deref())
.map(|row: sqlx::postgres::PgRow| {
    use sqlx::Row;
    TopEntry { key: row.get("entry_key"), count: row.get("cnt") }
})
.fetch_all(&self.pool)
.await?;
```

```rust
// Example for subquery #1 (total_blocked_logs, hardcoded 'block' overridable):
let total_blocked_logs: i64 = sqlx::query_scalar(
    r#"
    SELECT COUNT(*)::bigint FROM attack_logs
    WHERE action = COALESCE($3, 'block')
      AND ($1::int  IS NULL OR created_at >= NOW() - make_interval(hours => $1))
      AND ($2::text IS NULL OR host_code = $2)
    "#,
)
.bind(filter.hours.map(|h| i32::try_from(h).unwrap_or(i32::MAX)))
.bind(filter.host_code.as_deref())
.bind(filter.action.as_deref())
.fetch_one(&self.pool)
.await?;
```

```rust
// Example for subquery #11 (action_breakdown — host_code + hours only):
let action_breakdown: Vec<TopEntry> = sqlx::query(
    r#"
    SELECT action AS entry_key, COUNT(*)::bigint AS cnt
    FROM security_events
    WHERE ($1::int  IS NULL OR created_at >= NOW() - make_interval(hours => $1))
      AND ($2::text IS NULL OR host_code = $2)
    GROUP BY action
    ORDER BY cnt DESC
    "#,
)
.bind(filter.hours.map(|h| i32::try_from(h).unwrap_or(i32::MAX)))
.bind(filter.host_code.as_deref())
.map(|row: sqlx::postgres::PgRow| {
    use sqlx::Row;
    TopEntry { key: row.get("entry_key"), count: row.get("cnt") }
})
.fetch_all(&self.pool)
.await
.unwrap_or_default(); // preserve current resilience pattern from repo.rs:1056-1057
```

**Replace inline CASE in subqueries #10 + #12** with `category_of(rule_id)`. Net effect: lines `repo.rs:989-1021` collapse to `category_of(rule_id) AS category`; same for `repo.rs:1073-1105`. Total LOC reduction ≈ 60.

**Update internal callers of `get_stats_overview()`:**
Grep verification:
```bash
grep -Rn "get_stats_overview" crates/ --include="*.rs" | grep -v '/tests/' | grep -v '^[^:]*:[^:]*://'
```
Expected hits at time of plan: `crates/waf-api/src/stats.rs:28` (1 site). Update that call to `state.db.get_stats_overview(&StatsFilter::default()).await?` (phase 3 replaces `default()` with parsed query).

Tests referencing the function (phase 4 updates):
```bash
grep -Rn "get_stats_overview" crates/*/tests/ 2>/dev/null
```

### Step 5 — Compile gate

```bash
docker run --rm -v $PWD:/work -w /work rust:1.91-slim-bookworm \
  sh -c "cargo check -p waf-storage"
```

Must exit 0. If any `.unwrap()` introduced → revert + fix.

## Todo List

- [ ] **Grep-verify** current CASE branches in `repo.rs:990-1019` match step-1 migration verbatim (30 branches, hyphenated names, OWASP-942/941/930/931/932/933/913 + ADV-SSRF/SSTI + CRS-RESP + API-MASS + MODSEC-RESP placed BEFORE shorter prefixes).
- [ ] Confirm second inline CASE at `repo.rs:1074-1103` byte-equal to first (diff /tmp/case-live*.txt).
- [ ] Create `migrations/0009_category_function.sql` (LANGUAGE SQL IMMUTABLE — NOT plpgsql).
- [ ] Add `HeatmapCell`, `EndpointHeatmap`, `HeatmapFilter`, `StatsFilter` to `models.rs`.
- [ ] Add `get_endpoint_heatmap` to `repo.rs` with `make_interval` + `LEFT(path, 256)` + `'other'` rollup.
- [ ] Refactor `get_stats_overview` signature + replace inline CASE × 2 with `category_of()`.
- [ ] Thread filters per per-subquery matrix (12 subqueries, 4 of them with partial-filter rules).
- [ ] Update `stats_overview` handler call site to pass `&StatsFilter::default()` (finalized in phase 3).
- [ ] Run `cargo check -p waf-storage` via Docker.
- [ ] Run `cargo check -p waf-api` via Docker (call site change).

## Success Criteria

- [ ] `migrations/0009_category_function.sql` exists with **30 WHEN clauses + ELSE**, `LANGUAGE SQL IMMUTABLE`.
- [ ] `grep -c "WHEN rule_id LIKE" migrations/0009_category_function.sql` returns 30.
- [ ] `category_of('OWASP-942100')` returns `'sqli'` (longer-prefix branch fires before generic `OWASP-` — but generic `OWASP-` is NOT in the list; verify via psql in fixture).
- [ ] `category_of('CRS-RESP-1')` returns `'data-leakage'` (NOT `'owasp-crs'`), proving order.
- [ ] `get_stats_overview()` body contains ZERO `WHEN rule_id LIKE 'SQLI`: `grep -c "WHEN rule_id LIKE 'SQLI" crates/waf-storage/src/repo.rs` returns 0.
- [ ] All interval expressions in new/changed code use `make_interval(hours => $N::int)`; `grep -E "INTERVAL\s*'" crates/waf-storage/src/repo.rs` returns no NEW hits.
- [ ] `cargo check -p waf-storage` exits 0.
- [ ] No `.unwrap()`/`.expect()` in new code (outside `#[cfg(test)]`).

## Risk Assessment

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| Missed/reordered CASE branch → silent category drift | Med | **Critical** | Diff /tmp/case-live*.txt; phase 4 test asserts every prefix maps; spot-check `'CRS-RESP-1' → 'data-leakage'` and `'OWASP-942-x' → 'sqli'` |
| Wrong INTERVAL syntax | Med | High | Use proven `make_interval(hours => $N::int)` at `repo.rs:1161,1166`; grep gate above |
| Tail categories dropped (F3) → cells.sum() != total_events | Med | High | `'other'` rollup in CTE; phase 4 invariant test asserts sum equality |
| Filter applied to column that doesn't exist → query crash | Med | High | Per-subquery matrix locks which filter touches which table |
| `attack_logs` hardcoded `action='block'/'allow'` overridden incorrectly | Med | Med | `COALESCE($3, 'block')` / `COALESCE($3, 'allow')`; documented semantic |
| `LANGUAGE plpgsql` instead of `LANGUAGE SQL` blocks planner inlining | Low | Med | Migration template uses `LANGUAGE SQL IMMUTABLE`; comment in migration explains why |
| Long path payload | Low | Med | `LEFT(path, 256)` in SELECT and GROUP BY |
| `created_at TIMESTAMPTZ` + `NOW()` cross-tz drift | Low | Low | TIMESTAMPTZ is tz-safe by construction; `NOW()` returns UTC-equivalent timestamptz (I8 confirmation) |
| Migration fails on existing DB | Low | High | `CREATE OR REPLACE FUNCTION` idempotent |
| Path SQL injection | Low | High | `.bind()` parameterizes |

## Security Considerations

- All user input flows through `sqlx::query(...).bind(...)` → SQL injection mitigated.
- `category_of()` only reads rule_id strings; pure function, no side effects.
- No new privileges granted; function runs as connection user.

## Rollback Plan

1. Revert `repo.rs` + `models.rs` changes (`git revert` or branch reset before merge).
2. Apply rollback SQL: `DROP FUNCTION IF EXISTS category_of(TEXT);`.
3. Re-deploy previous binary.

Migration is additive → rollback is safe and instant.

## Next Steps

Phase 3 wires `get_endpoint_heatmap` + filtered `get_stats_overview` into HTTP handlers.
