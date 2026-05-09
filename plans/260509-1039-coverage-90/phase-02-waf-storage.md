# Phase 02 — waf-storage (db + repo) → 85%

## Context Links
- Baseline: `plans/260509-1039-coverage-90/plan.md`
- Crate: `crates/waf-storage/`
- Related: `migrations/` (sqlx 0001–0008)

## Overview
- **Priority:** P1 (blocks Phase 04 + Phase 07)
- **Status:** pending
- **Target:** 85% line (baseline 0.00% — zero existing tests)
- File ownership glob: `crates/waf-storage/**`

## Key Insights
- `repo.rs` is **1839 regions / 1519 lines, ZERO covered**. Every method is async sqlx → needs a real PostgreSQL.
- `db.rs` is the connection pool wrapper + broadcast channel — needs real `PgPool`.
- Cannot use mocks (CLAUDE.md Iron Rule #4 + `tester` agent rule). Must use **testcontainers-rs** with `postgres:16-alpine` (matches `docker-compose.yml`).
- Repo splits into ~10 domain repositories in summary doc but actually a flat `Database` impl in `repo.rs` — needs decomposition into per-domain test files.

## Requirements
- Each public CRUD method tested: create + read-back + update + delete + list happy path.
- Constraint violations (unique, FK, NOT NULL) → error path coverage.
- Broadcast channel: subscribe → trigger event → assert receive.

## Architecture
```
waf-storage/src/
├── db.rs        ← Pool + migrate + broadcast (51 regions)
├── repo.rs      ← All CRUD (1839 regions, 183 functions)
├── models.rs    ← sqlx FromRow types
├── error.rs     ← StorageError enum
└── lib.rs
```

## Related Code Files
**Modify:**
- `crates/waf-storage/Cargo.toml` — add `[dev-dependencies] testcontainers = "0.23"`, `testcontainers-modules = { version = "0.11", features = ["postgres"] }`, `tokio = { workspace = true, features = ["macros", "rt-multi-thread", "test-util"] }`.

**Create:**
- `crates/waf-storage/tests/common/mod.rs` — `start_postgres()` fixture: spin container, run migrations, return `Database`.
- `crates/waf-storage/tests/repo_hosts.rs`
- `crates/waf-storage/tests/repo_ip_lists.rs` (allow_ips, block_ips)
- `crates/waf-storage/tests/repo_url_lists.rs`
- `crates/waf-storage/tests/repo_admin_users.rs` (auth, refresh tokens)
- `crates/waf-storage/tests/repo_certificates.rs`
- `crates/waf-storage/tests/repo_custom_rules.rs`
- `crates/waf-storage/tests/repo_security_events.rs` (+ broadcast)
- `crates/waf-storage/tests/repo_attack_logs.rs`
- `crates/waf-storage/tests/repo_notifications.rs`
- `crates/waf-storage/tests/repo_plugins_tunnels_crowdsec.rs`
- `crates/waf-storage/tests/db_migrate_and_broadcast.rs`

## Implementation Steps
1. Add testcontainers dev-deps. Verify Docker present (skip tests with `#[cfg_attr(not(docker), ignore)]` env gate).
2. Build `tests/common/mod.rs::start_postgres()` returning `(Container<Postgres>, Database)`. Reuse one container per test file (lazy `OnceCell`) to amortise cold start.
3. For each domain test file: cover `create_*`, `get_*`, `list_*`, `update_*`, `delete_*` from `repo.rs`. Use property-driven random uuids/strings; assert `RETURNING` columns match input.
4. Error cases: duplicate code → `StorageError::Database(unique violation)`; missing FK; NULL constraint; oversized varchar.
5. `db_migrate_and_broadcast.rs`: subscribe to `event_tx`, insert security_event, assert subscriber receives JSON.
6. Sanity: run `cargo test -p waf-storage --test repo_hosts -- --test-threads=1` first to validate fixture before parallelizing.
7. Re-measure: `cargo llvm-cov -p waf-storage --summary-only`.

## Todo List
- [ ] Add testcontainers dev-deps + verify build
- [ ] `tests/common/mod.rs` shared fixture (≤80 LOC)
- [ ] `tests/repo_hosts.rs` — CRUD + LB-backend join (≤200 LOC)
- [ ] `tests/repo_ip_lists.rs` — allow + block, CIDR validation
- [ ] `tests/repo_url_lists.rs`
- [ ] `tests/repo_admin_users.rs` + refresh-token expiry
- [ ] `tests/repo_certificates.rs` (PEM upsert, cert lifecycle)
- [ ] `tests/repo_custom_rules.rs`
- [ ] `tests/repo_security_events.rs` — query filters + broadcast
- [ ] `tests/repo_attack_logs.rs` — geo JSONB roundtrip
- [ ] `tests/repo_notifications.rs`
- [ ] `tests/repo_plugins_tunnels_crowdsec.rs`
- [ ] `tests/db_migrate_and_broadcast.rs`
- [ ] `cargo llvm-cov -p waf-storage --summary-only` ≥ 85%
- [ ] All tests under 30s wall-clock per file (warm container)

## Success Criteria
- `cargo llvm-cov -p waf-storage --summary-only` ≥ 85%.
- All tests gate on `if std::env::var("DISABLE_DB_TESTS").is_ok() { eprintln!("skipped"); return; }` so CI can opt-out where Docker unavailable.
- README contributor note added: "Run `docker info` before `cargo test -p waf-storage`."

## Risk Assessment
- **High**: testcontainers cold-start adds ~3-5s per test file. Mitigate by reusing one container across all tests in a file via `OnceCell`.
- **Medium**: macOS ARM users need rosetta or arm64 image. Use `postgres:16-alpine` (multi-arch).
- **Low**: sqlx migrations from `../../migrations` path may break in workspace test layout — verify with smoke test first.

## Security Considerations
- Test container must NOT bind to host network — use docker-internal only.
- No real PII in fixtures; use `uuid::new_v4()` strings.

## Next Steps
- Phase 04 (waf-api) consumes the same `start_postgres()` fixture — extract to a small shared crate `crates/waf-storage-test-utils` if duplication grows beyond 2 callers.
