// security_events list/filter/pagination coverage.
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
use waf_storage::models::{CreateSecurityEvent, SecurityEventQuery};

async fn insert(fx: &common::PgFixture, host_code: &str, ip: &str, action: &str, country: Option<&str>) {
    fx.db
        .create_security_event(CreateSecurityEvent {
            host_code: host_code.into(),
            client_ip: ip.into(),
            method: "GET".into(),
            path: "/x".into(),
            rule_id: Some("R-1".into()),
            rule_name: "rule".into(),
            action: action.into(),
            detail: None,
            geo_info: country.map(|c| json!({"country": c, "iso_code": c.get(0..2).unwrap_or("XX")})),
        })
        .await
        .unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn list_paginates_and_filters_by_host_code() {
    let fx = start_postgres().await;
    for _ in 0..5 {
        insert(&fx, "h1", "1.1.1.1", "block", None).await;
    }
    for _ in 0..3 {
        insert(&fx, "h2", "2.2.2.2", "log", None).await;
    }

    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            host_code: Some("h1".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 5);
    assert_eq!(rows.len(), 5);

    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            page: Some(1),
            page_size: Some(2),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 8);
    assert_eq!(rows.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_filters_by_ip_action_country_iso() {
    let fx = start_postgres().await;
    insert(&fx, "h1", "9.9.9.9", "block", Some("Vietnam")).await;
    insert(&fx, "h1", "8.8.8.8", "log", Some("United States")).await;

    let (rows, _) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            client_ip: Some("9.9.9.9".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].client_ip, "9.9.9.9");

    let (rows, _) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            action: Some("log".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action, "log");

    let (rows, _) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            country: Some("United".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    let (rows, _) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            iso_code: Some("Vi".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);

    let (rows, _) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            rule_name: Some("rule".into()),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn list_clamps_page_size_and_handles_empty() {
    let fx = start_postgres().await;
    let (rows, total) = fx
        .db
        .list_security_events(&SecurityEventQuery {
            page: Some(0),
            page_size: Some(9999),
            ..SecurityEventQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 0);
    assert!(rows.is_empty());
}
