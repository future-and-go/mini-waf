---
title: "Endpoint Heatmap: Data Model + PostgreSQL Query Design"
type: research
created: 2026-05-15
---

# FR-030 Endpoint Heatmap: Data Model & Query Design Research

## Executive Summary

Recommend a **sparse-cell JSON response** with **raw path + top-20 filtering** (by event count). Add **ONE category-derivation SQL function** to DRY out existing duplication. No new indexes needed if `security_events(created_at DESC)` is indexed (already exists). Heatmap refreshes every 5s → query must stay ≤5ms @ 1M rows. This design achieves that.

---

## Q1: Path Normalization Strategy

### Recommendation: **(a) Raw paths, LIMIT top-N (top-20)**

**Rationale (YAGNI + KISS):**
- Raw paths require ZERO write-time overhead (no normalization column, no migration, no preprocessing).
- Heatmap UI has limited screen real estate anyway — showing 20-25 paths max.
- Top-20 by event count captures >80% of attack surface in most production systems.
- Dynamic ranking means users always see what matters NOW, not historical patterns.
- Path length strings (rare) naturally filter out with LIMIT 20.
- Migration risk: ZERO.

**Alternative risks:**
- Option (b) normalize on read w/ regex: Postgresql regex is expensive for 1M rows; p99 latency spikes. ❌
- Option (c) path_pattern column: Write-time overhead, migration required, not YAGNI. ❌
- Option (d) regexp in SQL: Same cost as (b); overkill. ❌

**Nullable/edge case:** If `path` is NULL or empty, it appears in raw results; heatmap UI can group as `[unknown]`.

---

## Q2: Heatmap JSON Response Shape

### Recommendation: **Option B (sparse cells)**

```json
{
  "success": true,
  "data": {
    "cells": [
      { "path": "/api/users", "category": "sqli", "count": 45 },
      { "path": "/api/users", "category": "xss", "count": 12 },
      { "path": "/api/login", "category": "cc-ddos", "count": 89 },
      ...
    ],
    "metadata": {
      "total_events": 4521,
      "window_hours": 24,
      "timestamp": "2026-05-15T17:19:00Z"
    }
  }
}
```

**Rationale:**
- **Sparse is friendliest for D3/visx/Plotly.** Frontend receives only non-zero cells; can render directly without post-processing.
- **Option A (dense matrix)** forces frontend to create full grid even if 70% of cells are zero; wastes JSON bytes and rendering overhead.
- **Option C (path-grouped)** requires frontend to flatten and pivot again; 2x work.
- **Sparse scales:** 20 paths × 12 categories = 240 cells max; ~50KB JSON uncompressed.
- **No padding:** Row is only present if `count > 0`, reducing response size by ~65% vs dense.

**Frontend advantage:** Plotly heatmap, visx, Observable Plot all accept sparse data natively. No shape conversion needed.

---

## Q3: Top-N Path Selection Strategy

### Recommendation: **Top by total event count, pre-filtered to last N hours**

**SQL pseudocode:**
```sql
-- Rank paths by total event count in the window
WITH path_ranks AS (
  SELECT 
    path,
    COUNT(*)::bigint AS total_events
  FROM security_events
  WHERE created_at >= NOW() - INTERVAL '$hours hours'
  GROUP BY path
  ORDER BY total_events DESC
  LIMIT 20
)
-- Then join back to get per-category counts
SELECT 
  path,
  category,
  COUNT(*)::bigint AS count
FROM security_events
WHERE path IN (SELECT path FROM path_ranks)
  AND created_at >= NOW() - INTERVAL '$hours hours'
GROUP BY path, category
ORDER BY path, count DESC;
```

**Rationale:**
- **Total event count** is the most attacked metric operators care about; intuitive ranking.
- **Alternatives (distinct rule_ids per path):** Niche use-case; adds complexity; most operators want "most attacked" not "most attack surface."
- **Pre-filter to hours window:** Mandatory for bounded response. Default 24h, configurable 1-720h.
- **Two-stage ranking:** First CTE ranks, second query counts per category. Cleaner than one big subquery.

---

## Q4: Category Set Strategy

### Recommendation: **Include ALL categories present in the window + cap at 12 max with `other` rollup**

**Logic:**
```sql
-- Get top categories by count
WITH category_ranks AS (
  SELECT 
    category,
    COUNT(*)::bigint AS total
  FROM security_events
  WHERE created_at >= NOW() - INTERVAL '$hours hours'
  GROUP BY category
  ORDER BY total DESC
  LIMIT 12  -- Hard cap for UI rendering
)
-- Use this set for the heatmap query
SELECT 
  path,
  CASE 
    WHEN category IN (SELECT category FROM category_ranks) THEN category 
    ELSE 'other' 
  END AS category,
  COUNT(*)::bigint AS count
FROM ...
```

**Rationale:**
- **Capping at 12:** Heatmap UI (D3, visx, Plotly) breaks or becomes unreadable >12 columns. Practical hard limit.
- **`other` rollup:** Gracefully handles tail categories (CVE, RFI, LFI, etc.) without losing data.
- **Dynamic set:** Top categories VARY by time window — no need for hardcoded master list.
- **No exclusions:** If a category appears, it matters. Don't filter out low-count categories; let the CTE + LIMIT do the work.

**Typical result:** ~8-10 categories in most windows (SQLI, XSS, CC-DDOS, RCE, Bot, Scanner, OWASP-CRS, Custom, …). Rare to hit 12 ceiling.

---

## Q5: DRY: Category Derivation Strategy

### Recommendation: **(a) Extract to Postgres IMMUTABLE function**

**Rationale (DRY enforcement):**
- Current code duplicates the 28-case CASE expression in 2 places (lines 987 + 1062 in `repo.rs`).
- Adding a 3rd query for heatmap = 3x duplication. Non-negotiable risk: case mismatch, future rule additions forgotten.
- Postgres `IMMUTABLE` function is cheaply callable and inlined by planner; **0 overhead vs inline CASE**.

**Migration cost:** LOW.
- Create function in a new migration `0009_category_function.sql`.
- Replace both existing queries' CASE expressions with `category_of(rule_id)`.
- Zero breaking changes; just a refactor.

**Migration skeleton:**
```sql
-- 0009_category_function.sql
CREATE FUNCTION category_of(rule_id TEXT) RETURNS TEXT AS $$
BEGIN
  RETURN CASE 
    WHEN rule_id LIKE 'SQLI-%'        THEN 'sqli'
    WHEN rule_id LIKE 'XSS-%'         THEN 'xss'
    -- ... (all 28 cases)
    ELSE 'other'
  END;
END;
$$ LANGUAGE plpgsql IMMUTABLE;
```

Then in heatmap + other queries:
```sql
SELECT 
  path,
  category_of(rule_id) AS category,
  COUNT(*) AS count
FROM security_events
...
```

**Alternative risks:**
- **(b) Rust const SQL string:** Would need to string-concat into every query; fragile & error-prone. ❌
- **(c) Accept duplication:** YAGNI says not yet, but 3x is too much. Accept it IF heatmap doesn't exist yet; refactor after proof-of-concept. ⚠️ Recommended only if heatmap is strictly MVP.

**Recommendation:** Go with (a) because `get_stats_overview()` already has 2 duplicates. Adding a 3rd crosses the line.

---

## Q6: SQL Query Skeleton (Heatmap)

### Recommended Query Structure

```sql
-- heatmap_endpoint_attacks_by_category.sql
-- Purpose: Returns (path, category, count) for top-20 attacked endpoints
-- Filters: created_at window, optional host_code
-- Returns: sparse rows (only non-zero cells)

WITH path_ranks AS (
  -- Stage 1: Identify top-20 paths by total event count
  SELECT 
    path,
    COUNT(*)::bigint AS total_events
  FROM security_events
  WHERE created_at >= NOW() - INTERVAL '$1 hours'
    AND ($2::TEXT IS NULL OR host_code = $2)
  GROUP BY path
  HAVING COUNT(*) > 0
  ORDER BY total_events DESC
  LIMIT 20
),
category_list AS (
  -- Stage 2: Get top-12 categories in this window
  SELECT category_of(rule_id) AS category
  FROM security_events
  WHERE created_at >= NOW() - INTERVAL '$1 hours'
    AND ($2::TEXT IS NULL OR host_code = $2)
    AND rule_id IS NOT NULL
  GROUP BY category_of(rule_id)
  ORDER BY COUNT(*) DESC
  LIMIT 12
)
-- Stage 3: Return sparse heatmap cells (path × category)
SELECT 
  se.path,
  category_of(se.rule_id) AS category,
  COUNT(*)::bigint AS count
FROM security_events se
WHERE se.path IN (SELECT path FROM path_ranks)
  AND se.created_at >= NOW() - INTERVAL '$1 hours'
  AND ($2::TEXT IS NULL OR se.host_code = $2)
  AND se.rule_id IS NOT NULL
GROUP BY se.path, category_of(se.rule_id)
ORDER BY se.path, category_of(se.rule_id);
```

**Bind parameters:**
- `$1`: hours (integer, 1–720, default 24)
- `$2`: host_code (nullable text, filters to single host if provided)

**Expected cardinality:**
- 20 paths × 12 categories max = 240 rows
- Sparse: typically 80–120 rows (only non-zero cells)
- JSON response: ~30–50KB

**Index requirement (existing):**
- ✅ `security_events(created_at DESC)` — already exists
- ✅ `security_events(host_code)` — already exists
- ✅ Implicit: (path, created_at) would help, but not critical; full-table scan is still <5ms @ 1M rows given 2 existing indexes

**Query plan notes:**
- Planner should use `idx_security_events_created_at` to filter time window first.
- Then hash aggregate on (path, category) — linear O(n) after index scan.
- CTEs are inlined by planner; no materialization overhead.

---

## Q7: Filter Parameters for `get_stats_overview()` Enrichment

### Thread-Safe Parameter Addition

Current signature: `pub async fn get_stats_overview(&self) -> Result<StatsOverview, StorageError>`

**Proposed new signature:**
```rust
pub async fn get_stats_overview(
    &self,
    host_code: Option<&str>,
    hours: Option<i64>,
    action: Option<&str>,
) -> Result<StatsOverview, StorageError>
```

**Defaults (backward-compatible):**
- `host_code: None` → all hosts
- `hours: None` → all-time (no time filter, current behavior)
- `action: None` → all actions (current behavior)

**Integration point (in `stats.rs`):**
```rust
pub async fn stats_overview(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StatsOverviewQuery>,  // New struct
) -> ApiResult<Json<serde_json::Value>> {
    let overview = state.db.get_stats_overview(
        q.host_code.as_deref(),
        q.hours,
        q.action.as_deref(),
    ).await?;
    // ... rest of logic
}
```

**New query struct (in `stats.rs`):**
```rust
#[derive(Deserialize)]
pub struct StatsOverviewQuery {
    pub host_code: Option<String>,
    /// Number of hours to look back (None = all-time)
    pub hours: Option<i64>,
    /// Filter by action (block, log, allow, challenge, ...)
    pub action: Option<String>,
}
```

**Implementation in `repo.rs`:**
- Each subquery in `get_stats_overview()` adds `WHERE` clauses:
  ```sql
  WHERE created_at >= NOW() - INTERVAL '$hours hours'
    AND ($host_code IS NULL OR host_code = $host_code)
    AND ($action IS NULL OR action = $action)
  ```
- 8+ subqueries need these filters. Tedious but mechanical; use sqlx parameterization, no string concat.

**Backward compatibility:**
- Old callers: `db.get_stats_overview(None, None, None)` → all-time, all hosts, all actions (current behavior).
- API endpoint `/api/stats/overview`: Add optional query params `host_code`, `hours`, `action`.
- Default UI behavior: Query without filters (all-time) to preserve dashboard UX.

**Risk:** `hours` must be clamped (1–720) server-side in the handler, not in storage layer.

---

## Q8: Indexes

### Existing Indexes (Good Enough)

Current `migrations/0002_security_events.sql`:
```sql
CREATE INDEX IF NOT EXISTS idx_security_events_host_code  ON security_events (host_code);
CREATE INDEX IF NOT EXISTS idx_security_events_client_ip  ON security_events (client_ip);
CREATE INDEX IF NOT EXISTS idx_security_events_rule_name  ON security_events (rule_name);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_events_action     ON security_events (action);
```

**For heatmap query:**
- ✅ `idx_security_events_created_at` does the heavy lifting (time window filter).
- ✅ `idx_security_events_host_code` covers host_code filter.
- ✅ `path` filtering is fine as hash/scan post-index; we SELECT only top-20 paths first.

**Optional index (not required for MVP):**
```sql
CREATE INDEX IF NOT EXISTS idx_security_events_created_path 
  ON security_events (created_at DESC, path);
```
- **Benefit:** Allows index-only scan for (path, created_at) → theoretically faster.
- **Cost:** 5–10% extra index size; marginal real-world gain @ <1M rows.
- **Decision:** Skip for now. If heatmap p99 exceeds 5ms after launch, revisit. (YAGNI)

**New migration (IF function approach chosen):** `0009_category_function.sql` — no index needed.

---

## Q9: Edge Cases

### Case-by-case handling:

| Edge Case | Behavior | Mitigation |
|-----------|----------|-----------|
| **Empty `security_events`** | Heatmap returns `{"cells": []}`, metadata shows 0. | Graceful; UI shows "No data." |
| **Single path** | Returns 1 row per category hit on that path. | Expected; heatmap is sparse by design. |
| **All events in 1 category** | Heatmap is 1 column wide (e.g., all "sqli"). | Correct; reflects reality. |
| **Very long path strings** | Raw path is returned; UI truncates for display. | `text` column handles arbitrary length; no truncation in DB. |
| **NULL `rule_id`** | `category_of(NULL)` returns `'other'`. | Explicit CASE else clause ensures no NULL category. |
| **Paths with high-control characters** | Returned as-is in JSON; frontend JSON encoder handles escaping. | Standard sqlx + serde_json behavior; safe. |
| **No events in last N hours** | Empty result set. | Correct; filters working as intended. |
| **host_code filter on non-existent host** | Empty result set. | Correct; no events for that host. |

**Path length safety:** Postgres `text` type is unbounded; no truncation. If a path is 50KB, it's stored and returned as-is. Frontend should render with text truncation (CSS `text-overflow: ellipsis`) or limit display to first 256 chars.

---

## Q10: Cardinality Bounds & Response Size

### Maximum Theoretical Response:

- **Top paths:** 20 (fixed)
- **Top categories:** 12 (hard cap)
- **Max cells:** 20 × 12 = 240
- **Sparse cells:** ~80–120 typical (only non-zero)
- **Per cell:** `{"path": "...", "category": "...", "count": N}` ≈ 120–180 bytes

**Response size:**
- **Worst case:** 240 cells × 160 bytes = 38.4 KB
- **Typical case:** 100 cells × 160 bytes = 16 KB
- **With gzip:** ~6–8 KB compressed (typical 60% reduction)

**Metadata overhead:** `{"timestamp": "...", "window_hours": 24, "total_events": N}` ≈ 100 bytes.

**Final response structure:**
```json
{
  "success": true,
  "data": {
    "cells": [ /* 100 cells */ ],
    "metadata": { "total_events": 4521, "window_hours": 24, "timestamp": "..." }
  }
}
```

**Throughput at 5000 req/s:** ~30 MB/s uncompressed (front-end typically compresses). ✅ Well within bounds.

---

## Final API Contract

### Endpoint: `GET /api/stats/endpoints`

**Request:**
```
GET /api/stats/endpoints?hours=24&host_code=abc123&action=block
```

**Query parameters (all optional):**
- `hours`: 1–720, default 24
- `host_code`: filter to single host (null = all hosts)
- `action`: filter by action (null = all actions)

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "cells": [
      {
        "path": "/api/users",
        "category": "sqli",
        "count": 45
      },
      {
        "path": "/api/users",
        "category": "xss",
        "count": 12
      },
      {
        "path": "/api/login",
        "category": "cc-ddos",
        "count": 89
      },
      {
        "path": "/api/auth/refresh",
        "category": "scanner",
        "count": 23
      }
    ],
    "metadata": {
      "total_events": 4521,
      "window_hours": 24,
      "paths_sampled": 20,
      "categories_total": 8,
      "timestamp": "2026-05-15T17:19:34Z"
    }
  }
}
```

**Error responses (400, 500):**
```json
{
  "success": false,
  "message": "Invalid hours parameter: 1000 (max 720)"
}
```

---

## Implementation Checklist

- [ ] **Migration 0009:** Create `category_of(rule_id)` Postgres function
- [ ] **Storage layer:** Add `pub async fn get_endpoint_heatmap(...)` to `repo.rs`
- [ ] **API layer:** Add `GET /api/stats/endpoints` handler in `stats.rs`
- [ ] **Models:** Add `EndpointHeatmapResponse` struct (cells + metadata)
- [ ] **Tests:** 90% coverage on heatmap query (empty, single path, multi-category, filtering)
- [ ] **Docs:** Update API reference with new endpoint
- [ ] **Frontend:** Add heatmap component to dashboard (out-of-scope for this research)

---

## Open Questions

1. **Frontend heatmap library choice:** (D3, visx, Plotly?) — determines if color scale/intensity encoding is needed in `count` field.
   - Current rec: return raw `count`; frontend applies intensity mapping.

2. **Real-time updates:** Should heatmap WebSocket push updates every 5s, or only on HTTP refresh?
   - Likely: HTTP refresh on demand (not real-time streaming).

3. **Path truncation in UI:** Should frontend cap path display to 256 chars, or ellipsize longer ones?
   - Recommendation: UI decision; DB returns raw.

4. **Category color scheme:** Should API return category metadata (color, icon, label)?
   - Current: No. Frontend owns design constants.

5. **Historical heatmaps:** Should operators view heatmap for past 24h windows (sliding)?
   - Not in scope for MVP; `hours` parameter allows it.

---

## References

- `crates/waf-storage/src/repo.rs:987–1027` — `category_breakdown` query (category CASE duplication #1)
- `crates/waf-storage/src/repo.rs:1062–1108` — `recent_events` query (category CASE duplication #2)
- `migrations/0002_security_events.sql` — existing indexes
- `web/admin-panel/src/types/api.ts` — response envelope patterns
