// custom_rules + sensitive_patterns + hotlink_configs + lb_backends coverage.
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
use waf_storage::models::{CreateCustomRule, CreateLbBackend, CreateSensitivePattern, UpsertHotlinkConfig};

#[tokio::test(flavor = "multi_thread")]
async fn custom_rule_create_get_list_toggle_delete() {
    let fx = start_postgres().await;
    let rule = fx
        .db
        .create_custom_rule(CreateCustomRule {
            host_code: "h1".into(),
            name: "block-xyz".into(),
            description: Some("blocks XYZ".into()),
            priority: Some(10),
            enabled: Some(true),
            condition_op: Some("and".into()),
            conditions: json!([{"field": "uri", "op": "contains", "value": "xyz"}]),
            action: Some("block".into()),
            action_status: Some(403),
            action_msg: Some("blocked".into()),
            script: None,
        })
        .await
        .unwrap();
    assert_eq!(rule.priority, 10);
    assert_eq!(rule.action, "block");

    let by_id = fx.db.get_custom_rule(rule.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, rule.id);

    assert_eq!(fx.db.list_custom_rules(None).await.unwrap().len(), 1);
    assert_eq!(fx.db.list_custom_rules(Some("h1")).await.unwrap().len(), 1);
    assert!(fx.db.list_custom_rules(Some("nope")).await.unwrap().is_empty());

    assert!(fx.db.set_custom_rule_enabled(rule.id, false).await.unwrap());
    let toggled = fx.db.get_custom_rule(rule.id).await.unwrap().unwrap();
    assert!(!toggled.enabled);
    assert!(!fx.db.set_custom_rule_enabled(uuid::Uuid::new_v4(), true).await.unwrap());

    assert!(fx.db.delete_custom_rule(rule.id).await.unwrap());
    assert!(!fx.db.delete_custom_rule(rule.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn custom_rule_defaults_apply_when_unset() {
    let fx = start_postgres().await;
    let rule = fx
        .db
        .create_custom_rule(CreateCustomRule {
            host_code: "h1".into(),
            name: "defaults".into(),
            description: None,
            priority: None,
            enabled: None,
            condition_op: None,
            conditions: json!([]),
            action: None,
            action_status: None,
            action_msg: None,
            script: None,
        })
        .await
        .unwrap();
    assert_eq!(rule.priority, 100);
    assert!(rule.enabled);
    assert_eq!(rule.condition_op, "and");
    assert_eq!(rule.action, "block");
    assert_eq!(rule.action_status, 403);
}

#[tokio::test(flavor = "multi_thread")]
async fn sensitive_pattern_lifecycle() {
    let fx = start_postgres().await;
    let p = fx
        .db
        .create_sensitive_pattern(CreateSensitivePattern {
            host_code: "h1".into(),
            pattern: "secret".into(),
            pattern_type: Some("word".into()),
            check_request: Some(true),
            check_response: Some(false),
            action: Some("block".into()),
            remarks: Some("PII".into()),
        })
        .await
        .unwrap();
    assert!(p.enabled);
    assert_eq!(p.pattern_type, "word");

    assert_eq!(fx.db.list_sensitive_patterns(Some("h1")).await.unwrap().len(), 1);
    assert_eq!(fx.db.list_sensitive_patterns(None).await.unwrap().len(), 1);
    assert!(fx.db.list_sensitive_patterns(Some("nope")).await.unwrap().is_empty());

    assert!(fx.db.delete_sensitive_pattern(p.id).await.unwrap());
    assert!(!fx.db.delete_sensitive_pattern(p.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn hotlink_config_upsert_overwrites_existing() {
    let fx = start_postgres().await;
    let first = fx
        .db
        .upsert_hotlink_config(UpsertHotlinkConfig {
            host_code: "h1".into(),
            enabled: Some(true),
            allow_empty_referer: Some(true),
            allowed_domains: Some(vec!["example.com".into()]),
            redirect_url: Some("https://block".into()),
        })
        .await
        .unwrap();
    let second = fx
        .db
        .upsert_hotlink_config(UpsertHotlinkConfig {
            host_code: "h1".into(),
            enabled: Some(false),
            allow_empty_referer: Some(false),
            allowed_domains: Some(vec!["a.com".into(), "b.com".into()]),
            redirect_url: None,
        })
        .await
        .unwrap();
    assert_eq!(first.host_code, second.host_code);
    assert!(!second.enabled);
    let domains = second.allowed_domains.as_array().unwrap();
    assert_eq!(domains.len(), 2);

    let got = fx.db.get_hotlink_config("h1").await.unwrap().unwrap();
    assert_eq!(got.id, second.id);
    assert!(fx.db.get_hotlink_config("nope").await.unwrap().is_none());

    assert_eq!(fx.db.list_hotlink_configs().await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn lb_backend_lifecycle_and_health() {
    let fx = start_postgres().await;
    let b = fx
        .db
        .create_lb_backend(CreateLbBackend {
            host_code: "h1".into(),
            backend_host: "10.0.0.1".into(),
            backend_port: 8080,
            weight: Some(5),
            enabled: Some(true),
            health_check_url: Some("/health".into()),
            health_check_interval_secs: Some(15),
        })
        .await
        .unwrap();
    assert_eq!(b.weight, 5);
    assert_eq!(b.health_check_interval_secs, 15);
    assert!(b.is_healthy); // schema default

    let listed = fx.db.list_lb_backends(Some("h1")).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert!(fx.db.list_lb_backends(Some("nope")).await.unwrap().is_empty());
    assert_eq!(fx.db.list_lb_backends(None).await.unwrap().len(), 1);

    fx.db.update_lb_backend_health(b.id, false).await.unwrap();
    let after = fx.db.list_lb_backends(Some("h1")).await.unwrap();
    assert!(!after[0].is_healthy);
    assert!(after[0].last_health_check.is_some());

    assert!(fx.db.delete_lb_backend(b.id).await.unwrap());
    assert!(!fx.db.delete_lb_backend(b.id).await.unwrap());
}
