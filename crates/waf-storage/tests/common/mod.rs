// Shared Postgres testcontainer fixture for waf-storage integration tests.
// Reused by Phase 04 (waf-api) and Phase 07 (waf-engine) — see those crates'
// tests/common/mod.rs (copy-paste this file or factor into a shared crate).
//
// Usage in any tests/*.rs:
//   #[path = "common/mod.rs"]
//   mod common;
//   use common::start_postgres;
//
//   #[tokio::test(flavor = "multi_thread")]
//   async fn test_xxx() {
//       let fx = start_postgres().await;
//       let _ = fx.db.list_hosts().await.unwrap();
//   }
//
// Each test file gets its own container so per-file `cargo test` parallelism
// is safe and a single crashing test cannot poison others. Cold-start ~3-5s.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use waf_storage::Database;

pub struct PgFixture {
    pub db: Database,
    // Drop order matters: db (sqlx pool) is dropped first, container second.
    _container: ContainerAsync<PostgresImage>,
}

/// Spin a fresh `postgres:16-alpine` container, run all migrations, return a
/// connected `Database`. Pinned tag matches `docker-compose.yml`.
pub async fn start_postgres() -> PgFixture {
    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("start postgres testcontainer");

    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");

    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let db = Database::connect(&url, 5).await.expect("db connect");
    db.migrate().await.expect("migrate");
    PgFixture {
        db,
        _container: container,
    }
}

/// Insert a single `security_events` row with `created_at = NOW() - INTERVAL hours_ago hours`.
/// Uses `make_interval(hours => $N::int)` (no string concat) — safe for parameterized tests.
pub async fn insert_event(
    pool: &sqlx::PgPool,
    host: &str,
    path: &str,
    rule_id: Option<&str>,
    action: &str,
    hours_ago: i64,
) {
    // Invariant: tests pass small positive offsets (1..200h). The .unwrap_or(0)
    // fallback would silently insert "now" instead of panicking, which keeps
    // the helper compatible with `#![deny(clippy::unwrap_used)]` upstream while
    // still being obvious if a future test accidentally passes a huge value.
    let hours_i32 = i32::try_from(hours_ago).unwrap_or(0);
    sqlx::query(
        "INSERT INTO security_events \
         (host_code, client_ip, method, path, rule_id, rule_name, action, detail, geo_info, created_at) \
         VALUES ($1, '1.2.3.4', 'GET', $2, $3, 'test-rule', $4, NULL, NULL, \
                 NOW() - make_interval(hours => $5::int))",
    )
    .bind(host)
    .bind(path)
    .bind(rule_id)
    .bind(action)
    .bind(hours_i32)
    .execute(pool)
    .await
    .expect("insert_event");
}
