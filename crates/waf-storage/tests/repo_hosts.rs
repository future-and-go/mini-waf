// Hosts CRUD coverage.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    unused_imports
)]

#[path = "common/mod.rs"]
mod common;

use common::{PgFixture, start_postgres};
use waf_storage::models::{CreateHost, UpdateHost};

fn sample_host() -> CreateHost {
    CreateHost {
        host: "example.com".into(),
        port: 80,
        ssl: false,
        guard_status: true,
        remote_host: "127.0.0.1".into(),
        remote_port: 8080,
        remote_ip: None,
        cert_file: None,
        key_file: None,
        remarks: Some("test".into()),
        start_status: true,
        log_only_mode: false,
        upstream_alpn: "h2h1".to_string(),
        upstream_skip_ssl_verify: false,
        defense_json: None,
    }
}

async fn fresh() -> PgFixture {
    start_postgres().await
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_get_then_list() {
    let fx = fresh().await;
    let created = fx.db.create_host(sample_host()).await.unwrap();
    assert_eq!(created.host, "example.com");
    assert_eq!(created.port, 80);
    assert_eq!(created.code.len(), 16);

    let by_id = fx.db.get_host(created.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, created.id);

    let by_code = fx.db.get_host_by_code(&created.code).await.unwrap().unwrap();
    assert_eq!(by_code.id, created.id);

    let listed = fx.db.list_hosts().await.unwrap();
    assert_eq!(listed.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn get_missing_returns_none() {
    let fx = fresh().await;
    let none = fx.db.get_host(uuid::Uuid::new_v4()).await.unwrap();
    assert!(none.is_none());
    let none = fx.db.get_host_by_code("nope").await.unwrap();
    assert!(none.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn update_partial_fields_persists() {
    let fx = fresh().await;
    let host = fx.db.create_host(sample_host()).await.unwrap();

    let upd = UpdateHost {
        host: Some("changed.example.com".into()),
        port: Some(443),
        ssl: Some(true),
        guard_status: None,
        remote_host: None,
        remote_port: None,
        remote_ip: None,
        cert_file: None,
        key_file: None,
        remarks: None,
        start_status: None,
        log_only_mode: Some(true),
        upstream_alpn: None,
        upstream_skip_ssl_verify: None,
        defense_json: None,
    };
    let updated = fx.db.update_host(host.id, upd).await.unwrap().unwrap();
    assert_eq!(updated.host, "changed.example.com");
    assert_eq!(updated.port, 443);
    assert!(updated.ssl);
    assert!(updated.log_only_mode);
    // Untouched field
    assert!(updated.guard_status);
}

#[tokio::test(flavor = "multi_thread")]
async fn update_missing_returns_none() {
    let fx = fresh().await;
    let upd = UpdateHost {
        host: Some("x".into()),
        port: None,
        ssl: None,
        guard_status: None,
        remote_host: None,
        remote_port: None,
        remote_ip: None,
        cert_file: None,
        key_file: None,
        remarks: None,
        start_status: None,
        log_only_mode: None,
        upstream_alpn: None,
        upstream_skip_ssl_verify: None,
        defense_json: None,
    };
    let res = fx.db.update_host(uuid::Uuid::new_v4(), upd).await.unwrap();
    assert!(res.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_existing_and_missing() {
    let fx = fresh().await;
    let host = fx.db.create_host(sample_host()).await.unwrap();
    assert!(fx.db.delete_host(host.id).await.unwrap());
    // Already gone
    assert!(!fx.db.delete_host(host.id).await.unwrap());
    // Random UUID
    assert!(!fx.db.delete_host(uuid::Uuid::new_v4()).await.unwrap());
    let listed = fx.db.list_hosts().await.unwrap();
    assert!(listed.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_remote_ip_errors() {
    let fx = fresh().await;
    let mut req = sample_host();
    req.remote_ip = Some("not-an-ip".into());
    let err = fx.db.create_host(req).await;
    assert!(err.is_err(), "invalid INET cast must error");
}
