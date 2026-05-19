# Cursor Prompt — PRX-WAF Backend: Close 2 API Gaps for Rule Analytics Dashboard

> **Scope:** `crates/waf-api` + `crates/waf-storage` — thêm 2 endpoint mới và 1 method storage.
> **Mục đích:** đóng 2 gap mà admin-panel React (prompt trước) cần:
>  1. `GET /api/security-events/{id}` — single event detail cho trang `/security-events/:id`.
>  2. `GET /api/stats/timeseries-by-category?hours=24&host_code=…` — stacked timeline theo attack category cho `/rule-analytics`.
> **Quy tắc tuyệt đối:** tuân thủ **Seven Iron Rules** trong `CLAUDE.md`. Edition 2024.

---

## 0. Bắt buộc đọc trước khi sửa

1. `CLAUDE.md` — Seven Iron Rules. KHÔNG `.unwrap()` ngoài `#[cfg(test)]`, KHÔNG dead code, KHÔNG `todo!()`/`unimplemented!()`, validate qua `cargo check`/`cargo clippy --all-targets --all-features -- -D warnings`.
2. `crates/waf-storage/src/models.rs` — `SecurityEvent`, `SecurityEventQuery`, `TimeSeriesPoint`, `TopEntry`.
3. `crates/waf-storage/src/repo.rs::list_security_events` + `get_stats_timeseries` + `get_stats_overview` — copy SQL pattern (CASE expression cho category đã có sẵn), tuyệt đối không bịa schema.
4. `crates/waf-storage/src/repo.rs` lookup ngay phía trên `list_security_events`, có `create_security_event` & broadcast — biết Repo nhận `&self` và trả `Result<_, StorageError>`.
5. `crates/waf-api/src/handlers.rs::list_security_events` — đây là pattern cần follow cho handler mới. Response envelope: `{"success": true, "data": …}`.
6. `crates/waf-api/src/stats.rs` — pattern handler stats + `TimeseriesQuery`.
7. `crates/waf-api/src/server.rs` — Router build, ghi nhận chính xác chỗ thêm route mới (block "Security events" và block "Phase 5: Stats" / cluster).
8. `crates/waf-api/src/error.rs` — `ApiError::{NotFound, BadRequest, Internal, Storage}`, `ApiResult<T>`. **`Storage` đã `#[from]` `StorageError`** ⇒ dùng `?` thẳng, KHÔNG cần map.
9. `migrations/0002_security_events.sql` — schema thực tế của `security_events`. Cột `created_at` là `TIMESTAMPTZ`. Cột `geo_info` là `JSONB nullable`. Cột `rule_id` là `TEXT nullable`. ID là `UUID`.

---

## 1. Endpoint #1 — `GET /api/security-events/{id}`

### 1.1. Storage layer — `crates/waf-storage/src/repo.rs`

Thêm method MỚI ngay dưới `list_security_events`:

```rust
/// Fetch a single security event by its UUID.
///
/// Returns `Ok(None)` when no row matches — callers map this to `404`.
pub async fn get_security_event(&self, id: Uuid) -> Result<Option<SecurityEvent>, StorageError> {
    Ok(
        sqlx::query_as::<_, SecurityEvent>("SELECT * FROM security_events WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?,
    )
}
```

KHÔNG sửa `SecurityEvent` struct (đã đầy đủ `geo_info: Option<serde_json::Value>` từ JSONB).

### 1.2. Handler — `crates/waf-api/src/handlers.rs`

Thêm handler MỚI ngay dưới `list_security_events`:

```rust
/// GET `/api/security-events/{id}` — fetch a single security event for the detail view.
///
/// Returns 404 when no row matches; surfaces storage errors via `ApiError::Storage`.
pub async fn get_security_event(
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let event = state
        .db
        .get_security_event(id)
        .await?
        .ok_or_else(|| ApiError::NotFound(format!("Security event {id} not found")))?;

    Ok(Json(json!({ "success": true, "data": event })))
}
```

`Path<Uuid>` đã có sẵn import qua `use axum::extract::{Path, Query, State};` ở đầu file — verify trước khi gõ, không thêm lặp.

### 1.3. Router wire — `crates/waf-api/src/server.rs`

Tìm chính xác dòng hiện tại:

```rust
// Security events
.route("/api/security-events", get(list_security_events))
```

Đổi thành:

```rust
// Security events
.route("/api/security-events", get(list_security_events))
.route("/api/security-events/{id}", get(get_security_event))
```

Import của `get_security_event` đã có nếu nó nằm trong `handlers.rs` cùng module — verify `use` statements ở đầu `server.rs` chỗ list handler.

---

## 2. Endpoint #2 — `GET /api/stats/timeseries-by-category`

### 2.1. Storage layer

#### 2.1.1. Thêm model `crates/waf-storage/src/models.rs`

Thêm sau `TimeSeriesPoint`:

```rust
/// Per-category time-bucket from `security_events`, used by the Rule Analytics
/// stacked timeline chart.
///
/// `ts` is bucketed to the hour boundary; `category` is derived inline by the
/// same `CASE rule_id LIKE …` expression already shared with
/// `get_stats_overview` and `RecentEvent.category` so the dashboard does not
/// need a second mapping table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryTimeSeriesPoint {
    pub ts: DateTime<Utc>,
    pub category: String,
    pub count: i64,
}
```

#### 2.1.2. Repo method `crates/waf-storage/src/repo.rs`

Thêm sau `get_stats_timeseries`:

```rust
pub async fn get_stats_timeseries_by_category(
    &self,
    host_code: Option<&str>,
    hours: i64,
) -> Result<Vec<CategoryTimeSeriesPoint>, StorageError> {
    // The CASE expression below mirrors the one in `get_stats_overview` so a
    // single source of truth maps rule_id prefixes to the dashboard's category
    // labels. Keep both in sync if either side gains a new prefix.
    let rows: Vec<CategoryTimeSeriesPoint> = sqlx::query(
        "SELECT \
            date_trunc('hour', created_at) AS ts, \
            CASE \
                WHEN rule_id LIKE 'SQLI-%'        THEN 'sqli' \
                WHEN rule_id LIKE 'XSS-%'         THEN 'xss' \
                WHEN rule_id LIKE 'RCE-%'         THEN 'rce' \
                WHEN rule_id LIKE 'TRAV-%'        THEN 'path-traversal' \
                WHEN rule_id LIKE 'SCAN-%'        THEN 'scanner' \
                WHEN rule_id LIKE 'BOT-%'         THEN 'bot' \
                WHEN rule_id LIKE 'CC-%'          THEN 'cc-ddos' \
                WHEN rule_id LIKE 'ADV-SSRF%'     THEN 'ssrf' \
                WHEN rule_id LIKE 'ADV-SSTI%'     THEN 'ssti' \
                WHEN rule_id LIKE 'ADV-%'         THEN 'advanced' \
                WHEN rule_id LIKE 'CRS-RESP%'     THEN 'data-leakage' \
                WHEN rule_id LIKE 'CRS-%'         THEN 'owasp-crs' \
                WHEN rule_id LIKE 'API-MASS%'     THEN 'mass-assignment' \
                WHEN rule_id LIKE 'API-%'         THEN 'api-security' \
                WHEN rule_id LIKE 'MODSEC-RESP%'  THEN 'web-shell' \
                WHEN rule_id LIKE 'MODSEC-%'      THEN 'modsecurity' \
                WHEN rule_id LIKE 'CVE-%'         THEN 'cve' \
                WHEN rule_id LIKE 'GEO-%'         THEN 'geo-blocking' \
                WHEN rule_id LIKE 'CUSTOM-%'      THEN 'custom' \
                WHEN rule_id LIKE 'IP-%'          THEN 'ip-rule' \
                WHEN rule_id LIKE 'URL-%'         THEN 'url-rule' \
                WHEN rule_id LIKE 'SENS-%'        THEN 'sensitive-data' \
                WHEN rule_id LIKE 'HOTLINK-%'     THEN 'anti-hotlink' \
                WHEN rule_id LIKE 'OWASP-942%'    THEN 'sqli' \
                WHEN rule_id LIKE 'OWASP-941%'    THEN 'xss' \
                WHEN rule_id LIKE 'OWASP-930%'    THEN 'lfi' \
                WHEN rule_id LIKE 'OWASP-931%'    THEN 'rfi' \
                WHEN rule_id LIKE 'OWASP-932%'    THEN 'rce' \
                WHEN rule_id LIKE 'OWASP-933%'    THEN 'php-injection' \
                WHEN rule_id LIKE 'OWASP-913%'    THEN 'scanner' \
                ELSE 'other' \
            END AS category, \
            COUNT(*)::bigint AS cnt \
         FROM security_events \
         WHERE created_at >= NOW() - make_interval(hours => $1::int) \
           AND ($2::text IS NULL OR host_code = $2) \
           AND rule_id IS NOT NULL \
         GROUP BY date_trunc('hour', created_at), category \
         ORDER BY ts ASC, category ASC",
    )
    .bind(i32::try_from(hours).unwrap_or(i32::MAX))
    .bind(host_code)
    .map(|row: sqlx::postgres::PgRow| {
        use sqlx::Row;
        CategoryTimeSeriesPoint {
            ts: row.get("ts"),
            category: row.get("category"),
            count: row.get("cnt"),
        }
    })
    .fetch_all(&self.pool)
    .await?;

    Ok(rows)
}
```

Đảm bảo `CategoryTimeSeriesPoint` được re-export trong `crates/waf-storage/src/lib.rs` cùng các models hiện có. Kiểm tra `lib.rs` xem có `pub use models::{…}` không; nếu có, thêm `CategoryTimeSeriesPoint` vào danh sách.

> **Lý do nhân bản CASE expression:** giữ SQL phẳng, KHÔNG tạo VIEW (đụng migrations, đụng versioning). Code comment phía trên đã yêu cầu giữ sync với `get_stats_overview` — nếu muốn refactor sau, làm trong PR riêng.

### 2.2. Handler — `crates/waf-api/src/stats.rs`

Thêm handler MỚI sau `stats_timeseries`. KHÔNG sửa `TimeseriesQuery` struct hiện có — nó đã có đủ `host_code` + `hours`:

```rust
/// GET `/api/stats/timeseries-by-category`
///
/// Same time semantics as `stats_timeseries` (hourly buckets, last `hours`
/// hours, optionally scoped to a single host) but rows are split by attack
/// category. Used by the Rule Analytics stacked timeline chart.
///
/// Response payload is a `Vec<CategoryTimeSeriesPoint>` wrapped in the
/// standard `{"success": true, "data": …}` envelope. Rows for an hour bucket
/// where no category fired are simply absent — the FE is responsible for
/// filling gaps when rendering.
pub async fn stats_timeseries_by_category(
    State(state): State<Arc<AppState>>,
    Query(q): Query<TimeseriesQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let hours = q.hours.unwrap_or(24).clamp(1, 720);
    let series = state
        .db
        .get_stats_timeseries_by_category(q.host_code.as_deref(), hours)
        .await?;
    Ok(Json(serde_json::json!({ "success": true, "data": series })))
}
```

### 2.3. Router wire — `crates/waf-api/src/server.rs`

Tìm cluster routes có mẫu `.route("/api/stats/…", get(stats_…))`. Hiện tại `server.rs` có:

```rust
.route("/api/stats/overview", get(stats_overview))
.route("/api/stats/timeseries", get(stats_timeseries))
.route("/api/stats/geo", get(stats_geo))
```

(Tìm chính xác trong file — nếu format khác, giữ format đó.) Thêm dòng:

```rust
.route("/api/stats/timeseries-by-category", get(stats_timeseries_by_category))
```

Import: section `use crate::stats::{stats_geo, stats_overview, stats_timeseries};` hoặc tương đương — thêm `stats_timeseries_by_category` vào danh sách import.

---

## 3. Tests

### 3.1. Storage tests — `crates/waf-storage/src/repo.rs`

Nếu file có module `#[cfg(test)] mod tests` với fixture DB sẵn (kiểm tra cuối file), thêm 2 tests sau pattern hiện có. Nếu KHÔNG có DB test fixture, **KHÔNG bịa** — bỏ qua test layer ở đây và chỉ giữ integration test ở section 3.2.

```rust
#[cfg(test)]
mod tests_security_event_detail {
    use super::*;
    // ... follow whatever fixture/setup helpers already exist in the file
    // (e.g. test_pool() / seed_event()). Do NOT create new fixtures.

    #[tokio::test]
    async fn get_security_event_returns_none_for_unknown_id() {
        // Use existing test pool helper; skip if not present.
    }

    #[tokio::test]
    async fn get_security_event_returns_row_for_known_id() {
        // Insert via existing create_security_event helper, then assert.
    }
}
```

> Nếu repo chưa có integration test infrastructure cho `Repo`, **bỏ section này** — tests sẽ ở 3.2 dưới dạng smoke test cho handler (mock DB là quá tốn công cho 1 thay đổi nhỏ).

### 3.2. Handler / route smoke tests

Tìm trong `crates/waf-api/` xem có module test nào dùng `axum::Router` + `oneshot` chưa (vd. `tests/` thư mục hoặc `#[cfg(test)] mod tests` trong handler files). Nếu CÓ pattern hiện có (vd. handler test cho `list_security_events`), thêm 2 cases:

1. `get_security_event` với UUID không tồn tại → 404, body JSON có `"error"`.
2. `stats_timeseries_by_category` với `hours=24` → 200, body `{success: true, data: []}` khi DB rỗng (clamp test).

Nếu repo chưa có handler-level test framework, **bỏ qua test ở đây**. KHÔNG bịa fixture, KHÔNG thêm dependency mới chỉ để test. Comment `// NOTE: handler-level tests deferred — no existing harness in waf-api` ở dưới handler tương ứng và chuyển trách nhiệm validate sang `cargo check` + manual curl.

---

## 4. Documentation update

### 4.1. `docs/system-architecture.md`

Trong section liệt kê API endpoints (block bắt đầu bằng `/api/security-events`), thêm dòng:

```
| `/api/security-events/{id}` | Single security event detail (UUID) |
| `/api/stats/timeseries-by-category` | Per-category hourly bucket counts, last N hours |
```

### 4.2. `docs/codebase-summary.md`

Trong block phân loại endpoint của `waf-api`, append 2 dòng tương ứng vào danh sách hiện có. Không tạo section mới.

### 4.3. `README.md`

Chỉ thêm vào section "REST API endpoints" nếu README đã liệt kê các route cụ thể. Nếu README chỉ tổng quan, BỎ QUA.

---

## 5. Constraints — không thương lượng

- **Rust Edition 2024**, no `.unwrap()` / `.expect()` ngoài `#[cfg(test)]`. Pattern hợp lệ: `?`, `.ok_or_else(|| ApiError::NotFound(…))`, `unwrap_or_default()`, `unwrap_or(value)`.
- **Không thêm dependency mới**. `sqlx`, `axum`, `serde_json`, `uuid`, `chrono` — đã có sẵn.
- **Không sửa migrations**. Schema `security_events` đủ dùng. Index `idx_security_events_created_at DESC` đã tồn tại nên `date_trunc + GROUP BY` không gây sequential scan với hours ≤ 720.
- **Không thay đổi response envelope hiện có** — luôn `{"success": true, "data": …}`. Refine data-provider phía FE unwrap dựa trên field `data`.
- **`unwrap_or(i32::MAX)` cho `i64 → i32`** đã đúng pattern của `get_stats_timeseries` — copy y nguyên, đừng đổi thành `try_into().map_err(...)?` vì sẽ phá symmetry.
- **Clamp `hours` 1..=720** ở handler, KHÔNG ở repo (giữ repo "thuần" nhận giá trị đã clamp).
- **`host_code` query param**: copy nguyên semantic của `stats_timeseries` — `None` = all hosts, `Some(s)` = filter equality.
- **Trailing slash & path style**: dùng `/api/security-events/{id}` (axum 0.8 syntax có sẵn), KHÔNG dùng `:id` style cũ.
- **`SecurityEvent` derive `Serialize`** đã sẵn (`#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]`) — JSON `geo_info` sẽ ra dạng object/null tự động.
- **Mọi tracing**: nếu thêm log, dùng `tracing::warn!` cho lỗi không-fatal, `tracing::info!` cho thành công đáng kể. KHÔNG `println!`.

---

## 6. Build & verify

Sau khi sửa code, chạy theo thứ tự:

```bash
cargo fmt --all
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace
cargo test --workspace
```

Mọi command phải exit 0. CI enforce `cargo fmt --all -- --check` strict.

### 6.1. Manual curl verification

Sau `cargo run --release`:

```bash
# Get JWT
TOKEN=$(curl -s -X POST http://localhost:16827/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"admin123"}' \
  | jq -r '.access_token')

# 1) List, pick an id
EVENT_ID=$(curl -s http://localhost:16827/api/security-events?page_size=1 \
  -H "Authorization: Bearer $TOKEN" | jq -r '.data[0].id')

# 2) Detail — should return {success: true, data: {...}}
curl -s http://localhost:16827/api/security-events/$EVENT_ID \
  -H "Authorization: Bearer $TOKEN" | jq .

# 3) Detail with bogus UUID — should return 404 + {error: "..."}
curl -s -w '\n%{http_code}\n' \
  http://localhost:16827/api/security-events/00000000-0000-0000-0000-000000000000 \
  -H "Authorization: Bearer $TOKEN"

# 4) Detail with malformed UUID — should return 400 from axum's Path extractor
curl -s -w '\n%{http_code}\n' \
  http://localhost:16827/api/security-events/not-a-uuid \
  -H "Authorization: Bearer $TOKEN"

# 5) Stacked timeline — last 24h, all hosts
curl -s "http://localhost:16827/api/stats/timeseries-by-category?hours=24" \
  -H "Authorization: Bearer $TOKEN" | jq '.data[:5]'

# 6) Stacked timeline — last 1h, single host
curl -s "http://localhost:16827/api/stats/timeseries-by-category?hours=1&host_code=demo" \
  -H "Authorization: Bearer $TOKEN" | jq '.data | length'

# 7) Stacked timeline — clamp test, hours=9999 must be clamped to 720
curl -s "http://localhost:16827/api/stats/timeseries-by-category?hours=9999" \
  -H "Authorization: Bearer $TOKEN" -w '\n%{http_code}\n'  # expect 200
```

---

## 7. Acceptance Criteria

Hoàn thành khi:

1. `cargo fmt --all -- --check` exit 0.
2. `cargo clippy --workspace --all-targets --all-features -- -D warnings` exit 0.
3. `cargo check --workspace` exit 0.
4. `cargo test --workspace` exit 0 (kể cả khi không thêm test mới — không được break test hiện có).
5. `GET /api/security-events/{valid-uuid}` trả 200 với body `{success:true, data:{id, host_code, client_ip, …, geo_info, created_at}}`.
6. `GET /api/security-events/{unknown-uuid}` trả 404 với body `{error:"Security event {uuid} not found"}`.
7. `GET /api/security-events/not-a-uuid` trả 400 (axum Path extractor reject — không phải lỗi handler).
8. `GET /api/stats/timeseries-by-category?hours=24` trả 200 với array, mỗi row có `ts` (RFC3339), `category` (string), `count` (number).
9. `GET /api/stats/timeseries-by-category?hours=9999` được clamp xuống 720 trong handler, vẫn trả 200.
10. `host_code` filter hoạt động — query với host không tồn tại trả `data: []`.
11. Frontend prompt trước (BACKEND-GAP markers) có thể remove các fallback và switch sang `useOne<SecurityEvent>({resource:'security-events', id})` + stacked timeline thật.

---

## 8. Output format

Trả về theo thứ tự:

1. Liệt kê file sửa: `crates/waf-storage/src/models.rs`, `crates/waf-storage/src/repo.rs`, `crates/waf-storage/src/lib.rs` (nếu cần re-export), `crates/waf-api/src/handlers.rs`, `crates/waf-api/src/stats.rs`, `crates/waf-api/src/server.rs`, `docs/system-architecture.md`, `docs/codebase-summary.md`.
2. Diff hoặc patch cụ thể cho từng file — KHÔNG dán toàn bộ file lớn, chỉ diff hunks.
3. Output `cargo check` / `cargo clippy` cuối cùng, dán 5 dòng đầu của output để xác nhận pass.
4. Checklist 11 acceptance criteria với cách verify đã làm được.

Không tóm tắt. Đi thẳng code.
