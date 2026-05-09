# Phase 04 — waf-api (handlers, middleware, ws) → 80%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-api/`
- Depends on: **Phase 02 (waf-storage)** — needs Postgres fixture.

## Overview
- **Priority:** P2
- **Status:** pending (BLOCKED on Phase 02)
- **Target:** 80% line (baseline 19.96%)
- File ownership glob: `crates/waf-api/**`

## Key Insights
- 14 of 22 files at 0%. axum handlers untested.
- Strategy: spin up the **real** `Router` via `axum::serve` against `tokio::net::TcpListener::bind("127.0.0.1:0")` and hit via `reqwest`. NO handler-mock or `oneshot()` shortcuts that bypass middleware.
- Each handler module (`hosts.rs`, `rules_api.rs`, `cluster.rs`, `crowdsec.rs`, etc.) gets one `tests/handler_<name>.rs` file.
- `server.rs` (377 regions, 0%): Router builder. Most lines exercised by spinning a server. Bootstrap branches for static-files / TLS may stay uncovered → accept ceiling.
- `auth.rs` already 66% — push to 90%, this is the security boundary.
- `security.rs` (620 regions, 87.58%) — already strong; minor edge cases.

## Requirements
- Each `pub fn` route handler hit at least once with valid auth + once unauthenticated.
- Middleware: JWT extract success + failure (missing/expired/malformed/wrong-sig).
- WebSocket: connect with valid JWT → receive event broadcast → close.
- Error mapping: `StorageError::NotFound` → 404, `StorageError::Validation` → 400, etc.

## Architecture
```
waf-api/src/
├── server.rs        ← 0% Router builder
├── state.rs         ← 0% (AppState constructor)
├── middleware.rs    ← 0%
├── auth.rs          ← 66% — push to 90%
├── handlers.rs      ← 7% (legacy aggregator)
├── error.rs         ← 0% (StorageError → IntoResponse)
├── health.rs        ← 0%
├── cluster.rs       ← 0%
├── crowdsec.rs      ← 0%
├── notifications.rs ← 0%
├── panel_api.rs     ← 0%
├── plugins.rs       ← 0%
├── tunnels.rs       ← 0%
├── stats.rs         ← 0%
├── static_files.rs  ← 0% (embedded UI)
├── websocket.rs     ← 0%
├── logs.rs          ← 16%
├── cache_api.rs     ← 34%
├── rule_sources_api.rs ← 51%
├── rules_api.rs     ← 39%
└── security.rs      ← 88% (skip)
```

## Related Code Files
**Modify:**
- `crates/waf-api/Cargo.toml` — add `[dev-dependencies] reqwest = { version = "0.12", features = ["json"] }`, `tokio-tungstenite = "0.24"`, `serde_json` (already present?), `tower = { version = "0.5", features = ["util"] }`, share testcontainers via Phase 02.

**Create:**
- `crates/waf-api/tests/common/mod.rs` — `TestServer { addr, db, jwt_admin: String }` fixture: spin postgres, seed admin, build Router, bind random port, return.
- `crates/waf-api/tests/auth_login_logout.rs` — login happy path, bad password, locked account, refresh, logout
- `crates/waf-api/tests/middleware_jwt.rs` — auth middleware acceptance + rejection
- `crates/waf-api/tests/handler_hosts_crud.rs`
- `crates/waf-api/tests/handler_rules_api.rs`
- `crates/waf-api/tests/handler_ip_url_lists.rs`
- `crates/waf-api/tests/handler_certificates.rs`
- `crates/waf-api/tests/handler_cluster_status.rs`
- `crates/waf-api/tests/handler_crowdsec.rs`
- `crates/waf-api/tests/handler_notifications.rs`
- `crates/waf-api/tests/handler_panel_config.rs`
- `crates/waf-api/tests/handler_plugins_tunnels.rs`
- `crates/waf-api/tests/handler_stats_logs.rs`
- `crates/waf-api/tests/handler_health.rs`
- `crates/waf-api/tests/handler_static_files.rs` (verify `/ui/*` 200, mime types)
- `crates/waf-api/tests/handler_cache_api.rs`
- `crates/waf-api/tests/handler_rule_sources_api.rs`
- `crates/waf-api/tests/websocket_events.rs` (subscribe + broadcast)
- `crates/waf-api/tests/error_mapping.rs`

## Implementation Steps
1. Build `tests/common/mod.rs` (≤150 LOC) — spin postgres via Phase 02 helper, seed admin, build router, bind, spawn `axum::serve` task, return handle. Implement `Drop` to abort task.
2. Login flow: POST `/api/auth/login` with `{username:"admin",password:"admin"}` → assert JWT shape; refresh; logout (revoke refresh).
3. Middleware: hit any protected endpoint without `Authorization` → 401; with malformed token → 401; with valid → 200.
4. Per-domain handler tests: list (empty + populated), create, get-by-id, update, delete, get-after-delete = 404.
5. Validation: send bad payload → 400 + body has error message.
6. WebSocket: open `ws://addr/ws/events?token=<jwt>`, trigger a security event via direct DB insert → assert WS receives.
7. Static files: GET `/ui/`, GET `/ui/index.html` → 200 + content-type. GET `/ui/missing` → 404.
8. Health: GET `/health` → 200 (no auth).
9. Error mapping: induce `StorageError::NotFound` (delete twice) → assert 404; `StorageError::Database(unique violation)` → 409.
10. `cargo llvm-cov -p waf-api --summary-only` after each batch.

## Todo List
- [ ] `tests/common/mod.rs` server fixture (≤150 LOC)
- [ ] auth login/logout/refresh
- [ ] middleware_jwt acceptance/rejection
- [ ] handler_hosts_crud
- [ ] handler_rules_api
- [ ] handler_ip_url_lists (allow + block IP/URL)
- [ ] handler_certificates
- [ ] handler_cluster_status
- [ ] handler_crowdsec
- [ ] handler_notifications
- [ ] handler_panel_config (validation: bad risk threshold order)
- [ ] handler_plugins_tunnels
- [ ] handler_stats_logs (filters, pagination)
- [ ] handler_health
- [ ] handler_static_files
- [ ] handler_cache_api
- [ ] handler_rule_sources_api
- [ ] websocket_events
- [ ] error_mapping (404/400/409/500)
- [ ] `cargo llvm-cov -p waf-api --summary-only` ≥ 80%

## Success Criteria
- ≥ 80% line. Per-file: `auth.rs` ≥ 90%, every handler module ≥ 70%, `server.rs` ≥ 60% (TLS bootstrap intentionally uncovered).
- Suite runs in < 60s with warm container.
- No flaky tests (reqwest with explicit timeouts).

## Risk Assessment
- **Medium**: WebSocket close-handshake races. Use `tokio::time::timeout(Duration::from_secs(2), ws.next())`.
- **Medium**: TOTP login path requires fixed secret + clock — inject via test config OR bypass TOTP for `admin` user in test build.
- **Medium**: 19 new test files × ~150 LOC each ≈ 2.8K LOC. Stay disciplined on file size.
- **Low**: axum stable API; test patterns well-established.

## Security Considerations
- All write endpoints must require JWT in tests.
- Test admin password seeded as random per-run, never `admin/admin`.
- Static-file tests must NOT expose path traversal (`/ui/../etc/passwd` → 400 or 404).

## Next Steps
- Phase 11 CI gate consumes `cargo llvm-cov -p waf-api` for floor enforcement.
