// notification_configs + notification_log coverage.
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
use waf_storage::models::CreateNotificationConfig;

fn cfg(name: &str, host: Option<&str>, event: &str, channel: &str) -> CreateNotificationConfig {
    CreateNotificationConfig {
        name: name.into(),
        host_code: host.map(str::to_owned),
        event_type: event.into(),
        channel_type: channel.into(),
        config_json: json!({"webhook": "https://example/hook"}),
        enabled: Some(true),
        rate_limit_secs: Some(60),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_config_create_get_list_delete() {
    let fx = start_postgres().await;
    let c1 = fx
        .db
        .create_notification_config(cfg("c1", Some("h1"), "block", "webhook"))
        .await
        .unwrap();
    let _ = fx
        .db
        .create_notification_config(cfg("c2", Some("h2"), "log", "email"))
        .await
        .unwrap();

    assert_eq!(c1.name, "c1");
    assert_eq!(c1.rate_limit_secs, 60);
    assert!(c1.enabled);

    let by_id = fx.db.get_notification_config(c1.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, c1.id);
    assert!(
        fx.db
            .get_notification_config(uuid::Uuid::new_v4())
            .await
            .unwrap()
            .is_none()
    );

    assert_eq!(fx.db.list_notification_configs(None).await.unwrap().len(), 2);
    let h1 = fx.db.list_notification_configs(Some("h1")).await.unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].id, c1.id);
    assert!(fx.db.list_notification_configs(Some("nope")).await.unwrap().is_empty());

    assert!(fx.db.delete_notification_config(c1.id).await.unwrap());
    assert!(!fx.db.delete_notification_config(c1.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_config_defaults_when_unset() {
    let fx = start_postgres().await;
    let c = fx
        .db
        .create_notification_config(CreateNotificationConfig {
            name: "defaults".into(),
            host_code: None,
            event_type: "block".into(),
            channel_type: "webhook".into(),
            config_json: json!({}),
            enabled: None,
            rate_limit_secs: None,
        })
        .await
        .unwrap();
    assert!(c.enabled);
    assert_eq!(c.rate_limit_secs, 300);
}

#[tokio::test(flavor = "multi_thread")]
async fn enabled_filter_and_last_triggered_update() {
    let fx = start_postgres().await;
    let c1 = fx
        .db
        .create_notification_config(cfg("a", None, "block", "webhook"))
        .await
        .unwrap();
    let _ = fx
        .db
        .create_notification_config(cfg("b", None, "log", "webhook"))
        .await
        .unwrap();

    let block_only = fx.db.get_enabled_notification_configs("block").await.unwrap();
    assert_eq!(block_only.len(), 1);
    assert_eq!(block_only[0].id, c1.id);

    fx.db.update_notification_last_triggered(c1.id).await.unwrap();
    let after = fx.db.get_notification_config(c1.id).await.unwrap().unwrap();
    assert!(after.last_triggered.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn notification_log_create_and_list() {
    let fx = start_postgres().await;
    let c = fx
        .db
        .create_notification_config(cfg("a", None, "block", "webhook"))
        .await
        .unwrap();

    fx.db
        .create_notification_log(Some(c.id), "block", "webhook", "sent", Some("ok"), None)
        .await
        .unwrap();
    fx.db
        .create_notification_log(None, "block", "webhook", "failed", None, Some("timeout"))
        .await
        .unwrap();

    let logs = fx.db.list_notification_log(10).await.unwrap();
    assert_eq!(logs.len(), 2);
    let statuses: Vec<&str> = logs.iter().map(|l| l.status.as_str()).collect();
    assert!(statuses.contains(&"sent"));
    assert!(statuses.contains(&"failed"));
}
