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
        http_redirect: false,
        preserve_host: true,
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
        http_redirect: None,
        preserve_host: None,
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
async fn update_remote_ip_empty_string_clears_pin_and_null_preserves_it() {
    let fx = fresh().await;
    let mut create = sample_host();
    create.remote_ip = Some("10.0.0.9".into());
    let host = fx.db.create_host(create).await.unwrap();
    assert_eq!(host.remote_ip.as_deref(), Some("10.0.0.9"));

    let clear = UpdateHost {
        host: None,
        port: None,
        ssl: None,
        guard_status: None,
        remote_host: None,
        remote_port: None,
        remote_ip: Some(String::new()),
        cert_file: None,
        key_file: None,
        remarks: None,
        start_status: None,
        log_only_mode: None,
        upstream_alpn: None,
        upstream_skip_ssl_verify: None,
        defense_json: None,
        http_redirect: None,
        preserve_host: None,
    };
    // COALESCE('', remote_ip) stores the empty string — the proxy filters
    // empty pins, so this is the effective "clear" the admin panel sends.
    let cleared = fx.db.update_host(host.id, clear).await.unwrap().unwrap();
    assert_eq!(cleared.remote_ip.as_deref(), Some(""));

    // Re-pin, then send NULL: COALESCE keeps the existing value. This is why
    // the frontend must send "" (not omit the field) to clear the pin.
    let repin = UpdateHost {
        remote_ip: Some("10.0.0.7".into()),
        ..clear_update_template()
    };
    let repinned = fx.db.update_host(host.id, repin).await.unwrap().unwrap();
    assert_eq!(repinned.remote_ip.as_deref(), Some("10.0.0.7"));

    let omit = clear_update_template();
    let unchanged = fx.db.update_host(host.id, omit).await.unwrap().unwrap();
    assert_eq!(unchanged.remote_ip.as_deref(), Some("10.0.0.7"));
}

fn clear_update_template() -> UpdateHost {
    UpdateHost {
        host: None,
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
        http_redirect: None,
        preserve_host: None,
    }
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
        http_redirect: None,
        preserve_host: None,
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
