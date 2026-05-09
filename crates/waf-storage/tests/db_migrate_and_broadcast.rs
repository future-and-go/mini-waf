// db.rs coverage: connect, migrate, pool(), subscribe_events + broadcast.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::start_postgres;
use waf_storage::models::CreateSecurityEvent;

#[tokio::test(flavor = "multi_thread")]
async fn migrate_creates_tables_and_pool_is_usable() {
    let fx = start_postgres().await;
    // pool() accessor smoke-test
    assert!(!fx.db.pool().is_closed());

    // A trivial query proves migrations executed and connectivity works.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM hosts")
        .fetch_one(fx.db.pool())
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_security_event_broadcasts_to_subscribers() {
    let fx = start_postgres().await;
    let mut rx = fx.db.subscribe_events();

    fx.db
        .create_security_event(CreateSecurityEvent {
            host_code: "h1".into(),
            client_ip: "1.2.3.4".into(),
            method: "GET".into(),
            path: "/x".into(),
            rule_id: Some("RULE-1".into()),
            rule_name: "rule-name".into(),
            action: "block".into(),
            detail: Some("d".into()),
            geo_info: None,
        })
        .await
        .unwrap();

    let evt = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
        .await
        .expect("broadcast within timeout")
        .expect("event present");
    assert_eq!(evt["host_code"], "h1");
    assert_eq!(evt["client_ip"], "1.2.3.4");
    assert_eq!(evt["action"], "block");
}

#[tokio::test(flavor = "multi_thread")]
async fn connect_with_invalid_url_errors() {
    use waf_storage::Database;
    // Localhost port 1 is reliably closed; pool connect must error fast.
    let res = Database::connect("postgres://nobody:nopass@127.0.0.1:1/none", 1).await;
    assert!(res.is_err(), "expected connection failure");
}
