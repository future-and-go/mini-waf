---
phase: 5
title: "FR-042 reputation status + refresh API (red-team patched)"
status: pending
priority: P1
effort: "5h"
dependencies: []
---

# Phase 5: FR-042 reputation status/refresh API

## Overview

Sub-issue #6 cần FE Settings page hiển thị: feed names, entry counts, last_refresh, error_count + manual refresh button. Hôm nay backend load reputation feeds ở startup + auto-refresh (existing `relay/intel/`), nhưng không expose status/control qua API.

## Requirements

**Functional:**
- `GET /api/reputation/status` (admin auth) → JSON:
  ```json
  {
    "feeds": [
      { "name": "tor_exit", "entry_count": 4823, "last_refreshed_at": "2026-05-18T10:00:00Z", "last_error": null, "status": "ok" },
      { "name": "bad_asn",  "entry_count": 1247, "last_refreshed_at": "2026-05-18T10:00:00Z", "last_error": "fetch_timeout", "status": "stale" }
    ]
  }
  ```
- `POST /api/reputation/refresh` (admin auth, no body) → trigger reload tất cả feeds, return 202 Accepted + reload job id.
- `GET /api/reputation/refresh/{job_id}` (optional, simple) — không, KISS: trả về 200 sau khi reload done sync (timeout 30s).

**Non-functional:**
- Status endpoint là read-only — không hold lock dài; snapshot từ in-memory `RelayConfig`.
- Refresh không block hot-path traffic (existing relay reload đã async).
- Audit: log mỗi refresh call vào tracing (admin acted).

## Architecture (red-team patched)

Có sẵn:
- 4 provider impl: `crates/waf-engine/src/relay/intel/{tor_feed,asn_feed,asn_feed_iptoasn,datacenter}.rs`.
- `intel_refresh_loop` ở `crates/waf-engine/src/relay/mod.rs:94` — auto refresh theo interval, **discard** `RefreshOutcome` (red-team F5.2 verified).
- Auth pattern thật: `require_auth` middleware (`waf-api/src/middleware.rs:21`) — KHÔNG có `AuthAdmin` extractor (red-team F5.4 fix). Copy pattern từ `rules_api::reload_rule_registry` (`server.rs:193`).

**Red-team F5.1 fix**: `state.engine.reload_reputation_feeds()` KHÔNG tồn tại. Hai options:
- (a) Thêm `IntelProvider::trigger_refresh(&self) -> Result<()>` trait method, intel_refresh_loop check signal qua `tokio::sync::Notify`.
- (b) Handler call `provider.refresh()` trực tiếp (bypass loop).

**Decision: (b)** — KISS, không phải refactor loop. Trade-off: 2 refresh có thể chạy concurrent (loop + manual). Mitigation: per-feed `Mutex<()>` (F5.3 fix) — handler `try_lock` trước khi refresh, return 409 Conflict nếu loop đang chạy.

**Red-team F5.2 fix**: status tracking là NEW infrastructure trên 4 providers. Dùng wrapper pattern thay vì inline:

```rust
pub struct TrackedProvider<P> {
    inner: P,
    state: Arc<RwLock<FeedState>>,
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
}

#[derive(Clone, Serialize)]
pub struct FeedState {
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub last_outcome: Option<RefreshOutcome>,
    pub entry_count: usize,
}

#[async_trait]
impl<P: IntelProvider> IntelProvider for TrackedProvider<P> {
    async fn refresh(&self) -> Result<RefreshOutcome> {
        let _guard = self.refresh_lock.try_lock()
            .map_err(|_| anyhow!("refresh already in flight"))?;
        let outcome = self.inner.refresh().await;
        let mut state = self.state.write();
        state.last_refreshed_at = Some(Utc::now());
        state.last_outcome = Some(outcome.clone()?);
        state.entry_count = self.inner.size();  // assume trait extends with size()
        Ok(outcome?)
    }
}
```

Inject wrapper tại `intel_refresh_loop` setup chỗ providers tạo ra.

**Snapshot accessor**: `RelayConfig::feed_status() -> Vec<FeedStatus>` clone state từng `TrackedProvider`.

```rust
// crates/waf-engine/src/relay/intel/status.rs
#[derive(Debug, Serialize, Clone)]
pub struct FeedStatus {
    pub name: &'static str,
    pub entry_count: usize,
    pub last_refreshed_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub status: FeedHealth,  // Ok / Stale / Failed
}
```

**Handlers**: 2 mới trong `crates/waf-api/src/`:
- `pub async fn reputation_status(State, Extension(user)) -> Json<...>` — `Extension(user)` injected by `require_auth` middleware; check `user.role == admin` inline (copy `reload_rule_registry` pattern).
- `pub async fn reputation_refresh(State, Extension(user)) -> Result<StatusCode, Error>` — same admin gate.

Wire vào router `server.rs`:
```rust
.route("/api/reputation/status", get(reputation_status))
.route("/api/reputation/refresh", post(reputation_refresh))
```

## Related Code Files

- Read: `crates/waf-engine/src/relay/intel/` (providers + current reload)
- Read: `crates/waf-engine/src/relay/reload.rs` (trigger function signature)
- Read: `crates/waf-api/src/server.rs` (router pattern)
- Read: `crates/waf-api/src/handlers.rs` hoặc `crates/waf-api/src/security.rs` (admin auth example)
- Create: `crates/waf-engine/src/relay/intel/status.rs` (~80 lines)
- Create: `crates/waf-api/src/reputation.rs` (~120 lines, 2 handlers)
- Modify: `crates/waf-engine/src/relay/intel/mod.rs` — `pub mod status;`
- Modify: `crates/waf-engine/src/relay/intel/{tor_exit,bad_asn,asn_classifier}.rs` — track `last_refreshed_at` + `last_error` (if not present)
- Modify: `crates/waf-api/src/server.rs` — register 2 routes
- Modify: `crates/waf-api/src/lib.rs` — `pub mod reputation;`
- Create: `crates/waf-api/tests/handler_reputation.rs` (~150 lines, 4 tests)

## Implementation Steps

1. **Add status tracking ở provider**:
   - Mỗi feed provider có inner state: `Arc<RwLock<FeedInternalState>>` với `last_refreshed_at`, `last_error`, `entry_count`.
   - Mỗi `refresh()` call update state.
2. **`FeedStatus` struct** + Serialize impl.
3. **`RelayConfig::feed_status()`** trả về `Vec<FeedStatus>` (iterate providers).
4. **API handlers**:
   - `reputation_status`: call `state.engine.relay_config().feed_status()` → Json.
   - `reputation_refresh`: iterate providers, gọi `provider.refresh()` qua spawned task; return 202 immediately + job_id; status query check `last_refreshed_at` change.
   - Auth: dùng `require_auth` middleware (verified `waf-api/src/middleware.rs:21`), check admin role trong handler — copy pattern từ `reload_rule_registry` (`server.rs:193`). KHÔNG dùng `AuthAdmin` (extractor không tồn tại).
   - Concurrent refresh: dùng `Mutex::try_lock` trên `refresh_lock` per provider → return 409 Conflict nếu in-flight (F5.3 fix).
5. **Router wire** trong `server.rs`.
6. **Integration tests**:
   - `status_returns_seeded_feeds`: setup engine với mock feed, GET /api/reputation/status, verify 2 feeds.
   - `status_requires_admin_auth`: no token → 401.
   - `refresh_triggers_reload`: POST /api/reputation/refresh + admin → 200, verify reload counter +1.
   - `refresh_requires_admin_auth`: no token → 401.

## Success Criteria

- [ ] 2 endpoints respond < 50ms p99 (status là pure in-memory).
- [ ] 4 integration tests pass.
- [ ] Coverage ≥ 90% trên `reputation.rs` + `intel/status.rs`.
- [ ] Existing relay tests không regress (`cargo test -p waf-engine relay_`).
- [ ] OpenAPI/docs (nếu codebase có) update — verify `docs/codebase-summary.md` mục API.

## Risk Assessment

- **Refresh blocking**: nếu reload sync mất > 30s (mạng slow), API timeout. Mitigation: spawn async + return 202 immediately. KEEP IT SIMPLE — chấp nhận 30s sync.
- **Auth bypass**: phải reuse `require_auth` middleware + inline `user.role == admin` check (copy từ `rules_api::reload_rule_registry` ở `server.rs:193`).
- **Race khi refresh + traffic concurrent**: existing reload đã handle (atomic swap), không thay đổi.

## Notes

- Endpoint `POST /api/reputation/refresh` không nhận body (idempotent trigger). Nếu sau này cần selective (`{"feed": "tor_exit"}`), backwards-compat: thêm optional body.
- Phase này độc lập với Phase 1-4 — có thể chạy song song.
