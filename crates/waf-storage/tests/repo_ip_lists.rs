// allow_ips + block_ips CRUD coverage.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::start_postgres;
use waf_storage::models::CreateIpRule;

#[tokio::test(flavor = "multi_thread")]
async fn allow_ip_create_list_filter_delete() {
    let fx = start_postgres().await;

    let a1 = fx
        .db
        .create_allow_ip(CreateIpRule {
            host_code: "h1".into(),
            ip_cidr: "10.0.0.0/8".into(),
            remarks: Some("internal".into()),
        })
        .await
        .unwrap();
    let _ = fx
        .db
        .create_allow_ip(CreateIpRule {
            host_code: "h2".into(),
            ip_cidr: "192.168.1.1/32".into(),
            remarks: None,
        })
        .await
        .unwrap();

    let all = fx.db.list_allow_ips(None).await.unwrap();
    assert_eq!(all.len(), 2);

    let h1 = fx.db.list_allow_ips(Some("h1")).await.unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].host_code, "h1");

    let h_missing = fx.db.list_allow_ips(Some("nope")).await.unwrap();
    assert!(h_missing.is_empty());

    assert!(fx.db.delete_allow_ip(a1.id).await.unwrap());
    assert!(!fx.db.delete_allow_ip(a1.id).await.unwrap());
    assert_eq!(fx.db.list_allow_ips(None).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn block_ip_create_list_filter_delete() {
    let fx = start_postgres().await;

    let b1 = fx
        .db
        .create_block_ip(CreateIpRule {
            host_code: "h1".into(),
            ip_cidr: "1.2.3.4/32".into(),
            remarks: Some("attacker".into()),
        })
        .await
        .unwrap();
    let _ = fx
        .db
        .create_block_ip(CreateIpRule {
            host_code: "h2".into(),
            ip_cidr: "5.6.7.0/24".into(),
            remarks: None,
        })
        .await
        .unwrap();

    let all = fx.db.list_block_ips(None).await.unwrap();
    assert_eq!(all.len(), 2);

    let h1 = fx.db.list_block_ips(Some("h1")).await.unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].ip_cidr, "1.2.3.4/32");

    assert!(fx.db.delete_block_ip(b1.id).await.unwrap());
    assert!(!fx.db.delete_block_ip(b1.id).await.unwrap());
    assert_eq!(fx.db.list_block_ips(None).await.unwrap().len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn allow_ip_unknown_id_delete_returns_false() {
    let fx = start_postgres().await;
    assert!(!fx.db.delete_allow_ip(uuid::Uuid::new_v4()).await.unwrap());
    assert!(!fx.db.delete_block_ip(uuid::Uuid::new_v4()).await.unwrap());
}
