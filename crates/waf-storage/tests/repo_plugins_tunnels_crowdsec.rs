// wasm_plugins + tunnels + audit_log + crowdsec coverage.
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

use common::start_postgres;
use serde_json::json;
use waf_storage::models::{
    AuditLogQuery, CreateCrowdSecEvent, CreateTunnel, CreateWasmPlugin, CrowdSecEventQuery, UpsertCrowdSecConfig,
};

#[tokio::test(flavor = "multi_thread")]
async fn wasm_plugin_lifecycle() {
    let fx = start_postgres().await;
    let p = fx
        .db
        .create_wasm_plugin(CreateWasmPlugin {
            name: "logger".into(),
            version: Some("1.2.3".into()),
            description: Some("logs".into()),
            author: Some("me".into()),
            wasm_binary: vec![0, 1, 2, 3],
            enabled: Some(true),
            config_json: Some(json!({"x": 1})),
        })
        .await
        .unwrap();
    assert_eq!(p.version, "1.2.3");
    assert_eq!(p.wasm_binary, vec![0, 1, 2, 3]);

    let by_id = fx.db.get_wasm_plugin(p.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, p.id);
    assert!(fx.db.get_wasm_plugin(uuid::Uuid::new_v4()).await.unwrap().is_none());

    assert_eq!(fx.db.list_wasm_plugins().await.unwrap().len(), 1);

    assert!(fx.db.set_wasm_plugin_enabled(p.id, false).await.unwrap());
    let after = fx.db.get_wasm_plugin(p.id).await.unwrap().unwrap();
    assert!(!after.enabled);
    assert!(!fx.db.set_wasm_plugin_enabled(uuid::Uuid::new_v4(), true).await.unwrap());

    assert!(fx.db.delete_wasm_plugin(p.id).await.unwrap());
    assert!(!fx.db.delete_wasm_plugin(p.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn wasm_plugin_defaults_when_unset() {
    let fx = start_postgres().await;
    let p = fx
        .db
        .create_wasm_plugin(CreateWasmPlugin {
            name: "minimal".into(),
            version: None,
            description: None,
            author: None,
            wasm_binary: vec![],
            enabled: None,
            config_json: None,
        })
        .await
        .unwrap();
    assert_eq!(p.version, "1.0.0");
    assert!(p.enabled);
}

#[tokio::test(flavor = "multi_thread")]
async fn tunnel_lifecycle_with_status_updates() {
    let fx = start_postgres().await;
    let t = fx
        .db
        .create_tunnel(
            &CreateTunnel {
                name: "t1".into(),
                token: "secret".into(),
                target_host: "10.0.0.1".into(),
                target_port: 8080,
                enabled: Some(true),
                protocol: None,
            },
            "hashed",
        )
        .await
        .unwrap();
    assert_eq!(t.name, "t1");
    assert_eq!(t.status, "disconnected");
    assert_eq!(t.token_hash, "hashed");

    let by_id = fx.db.get_tunnel(t.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, t.id);

    let by_hash = fx.db.get_tunnel_by_token_hash("hashed").await.unwrap().unwrap();
    assert_eq!(by_hash.id, t.id);
    assert!(fx.db.get_tunnel_by_token_hash("nope").await.unwrap().is_none());

    assert_eq!(fx.db.list_tunnels().await.unwrap().len(), 1);

    fx.db.update_tunnel_status(t.id, "connected").await.unwrap();
    let connected = fx.db.get_tunnel(t.id).await.unwrap().unwrap();
    assert_eq!(connected.status, "connected");
    assert!(connected.last_seen.is_some());

    fx.db.update_tunnel_status(t.id, "disconnected").await.unwrap();

    assert!(fx.db.delete_tunnel(t.id).await.unwrap());
    assert!(!fx.db.delete_tunnel(t.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_log_create_and_list_with_filters_and_pagination() {
    let fx = start_postgres().await;
    fx.db
        .create_audit_log(
            Some("alice"),
            "login",
            Some("user"),
            Some("u1"),
            Some(json!({"ok": true})),
            Some("1.1.1.1"),
        )
        .await
        .unwrap();
    fx.db
        .create_audit_log(Some("bob"), "delete_host", Some("host"), Some("h1"), None, None)
        .await
        .unwrap();
    fx.db
        .create_audit_log(None, "system_init", None, None, None, None)
        .await
        .unwrap();

    let (rows, total) = fx.db.list_audit_log(&AuditLogQuery::default()).await.unwrap();
    assert_eq!(total, 3);
    assert_eq!(rows.len(), 3);

    let (alice, _) = fx
        .db
        .list_audit_log(&AuditLogQuery {
            admin_username: Some("alice".into()),
            ..AuditLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(alice.len(), 1);
    assert_eq!(alice[0].action, "login");

    let (login, _) = fx
        .db
        .list_audit_log(&AuditLogQuery {
            action: Some("login".into()),
            ..AuditLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(login.len(), 1);

    let (page, total) = fx
        .db
        .list_audit_log(&AuditLogQuery {
            page: Some(1),
            page_size: Some(2),
            ..AuditLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn crowdsec_config_upsert_and_event_log() {
    let fx = start_postgres().await;
    let cfg = UpsertCrowdSecConfig {
        host_id: None,
        enabled: true,
        mode: "lapi".into(),
        lapi_url: Some("http://lapi".into()),
        api_key: None,
        appsec_endpoint: Some("http://appsec".into()),
        appsec_key: None,
        update_frequency_secs: Some(30),
        fallback_action: Some("block".into()),
    };
    let row = fx
        .db
        .upsert_crowdsec_config(&cfg, Some("apikey-enc".into()), Some("appsec-enc".into()))
        .await
        .unwrap();
    assert!(row.enabled);
    assert_eq!(row.mode, "lapi");
    assert_eq!(row.update_frequency_secs, 30);
    assert_eq!(row.fallback_action, "block");

    let got = fx.db.get_crowdsec_config().await.unwrap().unwrap();
    assert_eq!(got.id, row.id);
    assert_eq!(got.api_key_encrypted.as_deref(), Some("apikey-enc"));

    fx.db
        .log_crowdsec_event(&CreateCrowdSecEvent {
            host_id: None,
            client_ip: "1.2.3.4".into(),
            decision_type: "ban".into(),
            scenario: "scan".into(),
            action_taken: "block".into(),
            request_path: Some("/x".into()),
        })
        .await
        .unwrap();

    let (events, total) = fx
        .db
        .list_crowdsec_events(&CrowdSecEventQuery::default())
        .await
        .unwrap();
    assert_eq!(total, 1);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].client_ip.as_deref(), Some("1.2.3.4"));
}

#[tokio::test(flavor = "multi_thread")]
async fn get_crowdsec_config_returns_none_when_empty() {
    let fx = start_postgres().await;
    assert!(fx.db.get_crowdsec_config().await.unwrap().is_none());
}
