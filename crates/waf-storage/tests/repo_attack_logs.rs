// attack_logs insert + list/filter coverage including stats overview & timeseries.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use chrono::Utc;
use common::start_postgres;
use serde_json::json;
use waf_storage::models::{AttackLog, AttackLogQuery, CreateSecurityEvent};

fn log(host: &str, ip: &str, action: &str, country: Option<&str>) -> AttackLog {
    AttackLog {
        id: uuid::Uuid::new_v4(),
        host_code: host.into(),
        host: format!("{host}.example.com"),
        client_ip: ip.into(),
        method: "GET".into(),
        path: "/x".into(),
        query: Some("a=1".into()),
        rule_id: Some("R-1".into()),
        rule_name: "rule".into(),
        action: action.into(),
        phase: "request".into(),
        detail: Some("d".into()),
        request_headers: Some(json!({"User-Agent": "x"})),
        geo_info: country.map(|c| json!({"country": c, "iso_code": &c[..2.min(c.len())]})),
        created_at: Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn create_and_list_with_filters_and_pagination() {
    let fx = start_postgres().await;
    fx.db
        .create_attack_log(log("h1", "1.1.1.1", "block", Some("Vietnam")))
        .await
        .unwrap();
    fx.db
        .create_attack_log(log("h1", "2.2.2.2", "allow", Some("Japan")))
        .await
        .unwrap();
    fx.db
        .create_attack_log(log("h2", "3.3.3.3", "block", None))
        .await
        .unwrap();

    let (all, total) = fx.db.list_attack_logs(&AttackLogQuery::default()).await.unwrap();
    assert_eq!(total, 3);
    assert_eq!(all.len(), 3);

    let (h1, total) = fx
        .db
        .list_attack_logs(&AttackLogQuery {
            host_code: Some("h1".into()),
            ..AttackLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 2);
    assert_eq!(h1.len(), 2);

    let (block, _) = fx
        .db
        .list_attack_logs(&AttackLogQuery {
            action: Some("block".into()),
            ..AttackLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(block.len(), 2);

    let (by_ip, _) = fx
        .db
        .list_attack_logs(&AttackLogQuery {
            client_ip: Some("1.1.1.1".into()),
            ..AttackLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(by_ip.len(), 1);
    assert_eq!(by_ip[0].client_ip, "1.1.1.1");

    let (by_country, _) = fx
        .db
        .list_attack_logs(&AttackLogQuery {
            country: Some("Vie".into()),
            ..AttackLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(by_country.len(), 1);

    let (by_iso, _) = fx
        .db
        .list_attack_logs(&AttackLogQuery {
            iso_code: Some("Ja".into()),
            ..AttackLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(by_iso.len(), 1);

    let (page, total) = fx
        .db
        .list_attack_logs(&AttackLogQuery {
            page: Some(1),
            page_size: Some(2),
            ..AttackLogQuery::default()
        })
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_overview_aggregates_attack_logs_and_security_events() {
    let fx = start_postgres().await;
    fx.db
        .create_attack_log(log("h1", "1.1.1.1", "block", Some("Vietnam")))
        .await
        .unwrap();
    fx.db
        .create_attack_log(log("h1", "1.1.1.1", "allow", None))
        .await
        .unwrap();
    fx.db
        .create_security_event(CreateSecurityEvent {
            host_code: "h1".into(),
            client_ip: "1.1.1.1".into(),
            method: "GET".into(),
            path: "/x".into(),
            rule_id: Some("SQLI-1".into()),
            rule_name: "sqli".into(),
            action: "block".into(),
            detail: None,
            geo_info: Some(json!({"country": "Vietnam", "iso_code": "VN", "isp": "TestISP"})),
        })
        .await
        .unwrap();

    let stats = fx.db.get_stats_overview().await.unwrap();
    assert_eq!(stats.hosts_count, 0);
    assert_eq!(stats.total_blocked, 2);
    assert_eq!(stats.total_allowed, 1);
    assert_eq!(stats.total_requests, 3);
    assert_eq!(stats.unique_attackers, 1);
    assert!(stats.top_ips.iter().any(|t| t.key == "1.1.1.1"));
    assert!(stats.top_countries.iter().any(|t| t.key == "Vietnam"));
    assert!(stats.category_breakdown.iter().any(|t| t.key == "sqli"));
    assert!(stats.action_breakdown.iter().any(|t| t.key == "block"));
    assert!(!stats.recent_events.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn timeseries_returns_buckets_when_data_present() {
    let fx = start_postgres().await;
    fx.db
        .create_security_event(CreateSecurityEvent {
            host_code: "h1".into(),
            client_ip: "1.1.1.1".into(),
            method: "GET".into(),
            path: "/x".into(),
            rule_id: None,
            rule_name: "r".into(),
            action: "block".into(),
            detail: None,
            geo_info: None,
        })
        .await
        .unwrap();

    let series = fx.db.get_stats_timeseries(None, 24).await.unwrap();
    assert_eq!(series.len(), 1);
    assert_eq!(series[0].total, 1);
    assert_eq!(series[0].blocked, 1);

    let scoped = fx.db.get_stats_timeseries(Some("h1"), 24).await.unwrap();
    assert_eq!(scoped.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn geo_stats_returns_top_countries_and_distribution() {
    let fx = start_postgres().await;
    for c in ["Vietnam", "Vietnam", "Japan"] {
        fx.db
            .create_security_event(CreateSecurityEvent {
                host_code: "h1".into(),
                client_ip: "1.1.1.1".into(),
                method: "GET".into(),
                path: "/x".into(),
                rule_id: None,
                rule_name: "r".into(),
                action: "block".into(),
                detail: None,
                geo_info: Some(json!({
                    "country": c,
                    "iso_code": if c == "Vietnam" { "VN" } else { "JP" },
                    "city": "City",
                    "isp": "ISP",
                })),
            })
            .await
            .unwrap();
    }
    let stats = fx.db.get_geo_stats().await.unwrap();
    assert!(!stats.top_countries.is_empty());
    assert!(!stats.top_cities.is_empty());
    assert!(!stats.top_isps.is_empty());
    assert!(!stats.country_distribution.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_old_stats_returns_zero_when_table_empty() {
    let fx = start_postgres().await;
    let n = fx.db.delete_old_stats(30).await.unwrap();
    assert_eq!(n, 0);
}
