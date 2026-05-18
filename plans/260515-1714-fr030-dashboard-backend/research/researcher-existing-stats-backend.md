---
name: existing-stats-backend-analysis
description: Current dashboard/stats backend implementation analysis for FR-030
---

# Existing Stats Backend Analysis

## Executive Summary

Current implementation has 3 endpoints (`/api/stats/overview`, `/api/stats/timeseries`, `/api/stats/geo`) with NO filtering (except `host_code` on timeseries). Category derivation is hardcoded CASE expression duplicated 2x (DRY violation). Tests use real Postgres via testcontainers. No new endpoint `/api/stats/endpoints` exists yet.

---

## Q1: `security_events` Table Schema

**File:** `migrations/0002_security_events.sql:1-21`

```sql
CREATE TABLE IF NOT EXISTS security_events (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    host_code   TEXT NOT NULL,
    client_ip   TEXT NOT NULL,
    method      TEXT NOT NULL,
    path        TEXT NOT NULL,
    rule_id     TEXT,
    rule_name   TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail      TEXT,
    geo_info    JSONB,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Columns:
- `id` (UUID, PK)
- `host_code` (TEXT, indexed)
- `client_ip` (TEXT, indexed)
- `method` (TEXT)
- `path` (TEXT)
- `rule_id` (TEXT, nullable)
- `rule_name` (TEXT, indexed)
- `action` (TEXT, indexed)
- `detail` (TEXT, nullable)
- `geo_info` (JSONB, nullable — contains `country`, `iso_code`, `city`, `isp`)
- `created_at` (TIMESTAMPTZ DESC indexed)

**Alternative log source:** `attack_logs` table (migration 0001) has similar fields but older schema with INET for IPs + REQUEST_HEADERS JSONB; detector now logs to `security_events` only.

---

## Q2: Category Derivation Pattern

**DRY Violation Identified:** CASE expression appears **TWICE** in same function (lines 989-1027 and 1073-1108).

**Pattern — Category breakdown query (repo.rs:987-1038):**

```sql
SELECT category AS entry_key, COUNT(*)::bigint AS cnt FROM (
    SELECT CASE
        WHEN rule_id LIKE 'SQLI-%'        THEN 'sqli'
        WHEN rule_id LIKE 'XSS-%'         THEN 'xss'
        ... [21 branches]
        ELSE 'other'
    END AS category
    FROM security_events
    WHERE rule_id IS NOT NULL
) s
GROUP BY category
ORDER BY cnt DESC
LIMIT 20
```

**Second occurrence (recent_events, lines 1062-1108):** Same 21-branch CASE expression inline in SELECT for `RecentEvent` mapping.

**Root cause:** No centralized function. SQL is built as string literals; `sqlx` maps inline to `TopEntry` and `RecentEvent` via closure.

**Approach to extract DRY:** Create helper function (Rust-side) to generate the CASE string literal once, or move CASE to a PostgreSQL **user-defined function** (not recommended here — adds DB migration burden). **Best: Rust enum + match, compute category in app after SELECT.*\***.

---

## Q3: API Handler Response Shape

**File:** `crates/waf-api/src/stats.rs:28-87` (stats_overview handler)

Pattern — **Envelope wrapper** with `success` boolean:

```rust
Ok(Json(serde_json::json!({
    "success": true,
    "data": {
        "total_requests": total_requests,
        "total_blocked": total_blocked,
        // ... 13 fields
    }
})))
```

**All 3 endpoints follow same envelope:** `{ "success": true, "data": <T> }` or `{ error: "msg" }` on error.

**Handler signature:** `async fn(State(state), Query(q)?) -> ApiResult<Json<serde_json::Value>>`

---

## Q4: Storage Layer Test Pattern

**Real Postgres, testcontainers-based. Two test setups:**

**Integration (waf-storage crate):**
- **File:** `crates/waf-storage/tests/common/mod.rs:1-50`
- Fixture: `pub async fn start_postgres() -> PgFixture` spins fresh `postgres:16-alpine` container
- Runs all migrations, returns `Database` handle
- Per-test-file container for parallelism safety (cold-start ~3-5s)
- Drop semantics: sqlx pool drops first, then container

**Example test (repo_security_events.rs:32-81):**

```rust
#[tokio::test(flavor = "multi_thread")]
async fn list_filters_by_ip_action_country_iso() {
    let fx = start_postgres().await;
    insert(&fx, "h1", "9.9.9.9", "block", Some("Vietnam")).await;
    let (rows, _) = fx.db.list_security_events(&SecurityEventQuery {
        client_ip: Some("9.9.9.9".into()),
        ..SecurityEventQuery::default()
    }).await.unwrap();
    assert_eq!(rows.len(), 1);
}
```

---

## Q5: API Handler Test Pattern

**Integration tests via real Postgres + real AppState.**

**File:** `crates/waf-api/tests/common/mod.rs:56-122`

Fixture: `pub async fn start_test_server() -> TestServer` returns:
- `addr: SocketAddr` (server listening on 127.0.0.1:0)
- `db: Arc<Database>` (for direct seeding)
- `admin_token: String` (valid JWT)
- Real Axum router with production `AppState`

**Example (handler_stats_logs.rs:20-29):**

```rust
#[tokio::test(flavor = "multi_thread")]
async fn stats_overview_ok() {
    let s = start_test_server().await;
    let resp = client()
        .get(url_for(s.addr, "/api/stats/overview"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}
```

**No mocks — all queries hit real DB.** This matches coverage floor expectations (waf-api: 78%).

---

## Q6: AppState Shape

**File:** `crates/waf-api/src/state.rs:12-68`

```rust
pub struct AppState {
    pub db: Arc<Database>,           // ← Postgres via sqlx
    pub engine: Arc<WafEngine>,
    pub router: Arc<HostRouter>,
    pub request_counter: Arc<AtomicU64>,
    pub blocked_counter: Arc<AtomicU64>,
    pub ws_connections: Arc<AtomicU32>,
    pub jwt_secret: String,
    pub notif_rate_limiter: NotifRateLimiter,
    pub cache: Arc<ResponseCache>,
    // ... 8+ other fields (plugins, tunnels, crowdsec, cluster, etc.)
}

impl AppState {
    pub fn total_requests(&self) -> u64 { /* ... */ }
    pub fn total_blocked(&self) -> u64 { /* ... */ }
}
```

**Database methods:** All on `Database` (waf-storage), not AppState. Called via `state.db.get_stats_overview().await?` etc.

---

## Q7: Error Type & ApiResult

**File:** `crates/waf-api/src/error.rs:1-46`

```rust
#[derive(Error, Debug)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("Bad request: {0}")]
    BadRequest(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Too many requests: {0}")]
    TooManyRequests(String),
    #[error("Internal server error: {0}")]
    Internal(#[from] anyhow::Error),
    #[error("Storage error: {0}")]
    Storage(#[from] waf_storage::StorageError),
}

pub type ApiResult<T> = Result<T, ApiError>;
```

**Usage in handler:** `async fn stats_overview(...) -> ApiResult<Json<...>>` — `?` propagates `StorageError` automatically.

---

## Q8: Query Param Parsing

**File:** `crates/waf-api/src/stats.rs:13-18`

```rust
#[derive(Deserialize)]
pub struct TimeseriesQuery {
    pub host_code: Option<String>,
    pub hours: Option<i64>,
}

pub async fn stats_timeseries(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,  // ← serde extracts from ?query=...
) -> ApiResult<Json<serde_json::Value>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 720);  // Default 24, max 720
    // ...
}
```

**Pattern:** Struct with `#[derive(Deserialize)]` + `Query<T>` extractor. Already in use.

---

## Q9: Category Derivation Refactoring Opportunity

**Current state:** CASE expression duplicated in lines 987-1027 (breakdown) and 1073-1108 (recent events).

**Best fix: Rust-side enum + match after SELECT.*\***

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackCategory {
    Sqli, Xss, Rce, PathTraversal, Scanner, Bot, CcDdos,
    // ... (18 more)
}

impl AttackCategory {
    pub fn from_rule_id(rule_id: Option<&str>) -> Self {
        match rule_id {
            Some(id) if id.starts_with("SQLI-") => Self::Sqli,
            Some(id) if id.starts_with("XSS-") => Self::Xss,
            // ... (19 more)
            _ => Self::Other,
        }
    }
}
```

Then in repo.rs: `SELECT rule_id FROM security_events ... GROUP BY rule_id`, map to category in Rust. Trades CPU for simpler schema, removes DB migration.

**Alternatively: PostgreSQL function** `fn get_attack_category(rule_id TEXT)` and reuse via `SELECT get_attack_category(rule_id) AS category`.

---

## Q10: Build & Test Commands

**For Docker (no local Rust required):**

```bash
# Run unit + integration tests for waf-api crate
docker run --rm \
  -v $PWD:/work -w /work \
  rust:1.91-slim-bookworm \
  bash -c "apt-get update && apt-get install -y postgresql-client && cargo test -p waf-api --lib --tests"

# Run with real Postgres (via testcontainers — docker socket required)
docker run --rm \
  -v $PWD:/work -w /work \
  -v /var/run/docker.sock:/var/run/docker.sock \
  rust:1.91-slim-bookworm \
  bash -c "apt-get update && apt-get install -y && cargo test -p waf-api"
```

**Local (Rust 1.91+):**

```bash
cargo test -p waf-api -- --test-threads=1
cargo test -p waf-storage --test repo_security_events -- --nocapture
```

---

## Q11: Coverage Tool & CI

**Tool:** `cargo-llvm-cov` (installed via GitHub action `taiki-e/install-action@cargo-llvm-cov`)

**File:** `.github/workflows/coverage.yml:60-63`

```yaml
- uses: taiki-e/install-action@cargo-llvm-cov
- name: Enforce coverage floor
  run: bash .github/scripts/coverage-check.sh ${{ matrix.crate }} ${{ matrix.floor }}
```

**Coverage floors (by crate):**
- `waf-api`: 78% floor
- `waf-storage`: 82% floor

**Command pattern:**
```bash
cargo llvm-cov -p waf-api --fail-under-lines=78 --lcov --output-path lcov.info
```

**For FR-030: target 90% on NEW handlers** (override floor if needed via script adjustment).

---

## Q12: Pagination/Sort Patterns

**Existing pattern in `list_security_events`:**

Struct: `SecurityEventQuery` with `page: Option<i32>`, `page_size: Option<i32>`

SQL pattern (repo.rs):
```sql
SELECT ... FROM security_events
WHERE <filters>
ORDER BY created_at DESC
LIMIT $1 OFFSET $2
```

**For `/api/stats/endpoints` (path × category heatmap):**
- No pagination needed (return all combinations, ~200 rows max if 50 paths × 4 categories)
- GROUP BY path, category
- ORDER BY count DESC, path ASC (deterministic)

---

## Things to Reuse ✓

1. **Response envelope:** `{ "success": true, "data": {...} }` — use serde_json::json! macro
2. **Test fixture:** `start_test_server()` from `crates/waf-api/tests/common/mod.rs` — use existing
3. **Query param struct:** `#[derive(Deserialize)] struct Query { ... }` + `Query<T>` extractor
4. **Error handling:** `ApiResult<T>` + `.await?` propagation
5. **Time-window pattern:** `.clamp(1, 720)` for hours (already in timeseries)
6. **Date truncation:** `date_trunc('hour', created_at)` in SQL for bucketing
7. **JSONB extraction:** `geo_info->>'field'` pattern for nested JSON

---

## Things to Avoid ✗

1. **Duplicated CASE expressions:** Extract category logic to single source (Rust enum or DB function)
2. **Hardcoded LIMIT 20:** Use query param for result limit (with ceiling)
3. **Unwrap/expect in production:** Use `.await?` + `ApiResult`
4. **.unwrap_or_default() silently:** Return explicit empty Vec if query matches nothing
5. **String-interpolated SQL:** All queries already parameterized via `sqlx::query(...).bind()` — maintain
6. **IN-memory caching of stats:** Not done currently; don't add without caching layer (moka already used for response cache)

---

## Open Questions & Unresolved

1. **Endpoint heatmap response format:** Should `GET /api/stats/endpoints?hours=24` return:
   - `{ path, category, count }` array (flat)?
   - `{ path: { category: count } }` (nested)?
   - `{ categories: [ ... ], paths: [ ... ], matrix: [[...]] }` (separate arrays)?
   
   *Recommendation:* Flat array for simplicity + FE-side grouping (matches existing TimeSeries pattern).

2. **Filter on /api/stats/overview:** Which new filters should be applied?
   - `host_code=xyz` — filter all breakdowns to single host?
   - `action=block` — filter to specific action type?
   - `hours=24` — time window (apply to category/action breakdowns)?
   
   *Recommendation:* All three; override the full stats with filtered results.

3. **Performance: GROUP BY path with 1M+ events:** Should we pre-aggregate to `request_stats` table (0004_auth_and_stats.sql) instead of live query?
   - Current `security_events` has no explicit aggregation table
   - `request_stats` exists but appears unused for live queries
   
   *Recommendation:* Live query first (simpler), add caching/aggregation if latency exceeds 1s in prod.

4. **Test coverage target for NEW code:** 90% stated — does this apply to:
   - New handler functions only?
   - New repo query functions?
   - Both + integration tests?
   
   *Recommendation:* Both handlers + repo layer (mirror existing waf-api:78%, waf-storage:82% coverage pattern).

5. **Missing dependency:** Are we guaranteed `hours` query param validation (1–720) applies to BOTH new endpoints, or only timeseries?
   
   *Recommendation:* Apply to both; extract to shared helper function to avoid duplication.

