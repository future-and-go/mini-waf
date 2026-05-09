// allow_urls + block_urls CRUD coverage.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use common::start_postgres;
use waf_storage::models::CreateUrlRule;

#[tokio::test(flavor = "multi_thread")]
async fn allow_url_lifecycle() {
    let fx = start_postgres().await;

    let r1 = fx
        .db
        .create_allow_url(CreateUrlRule {
            host_code: "h1".into(),
            url_pattern: "/api/public".into(),
            match_type: "prefix".into(),
            remarks: Some("public api".into()),
        })
        .await
        .unwrap();
    let _ = fx
        .db
        .create_allow_url(CreateUrlRule {
            host_code: "h2".into(),
            url_pattern: "/health".into(),
            match_type: "exact".into(),
            remarks: None,
        })
        .await
        .unwrap();

    assert_eq!(fx.db.list_allow_urls(None).await.unwrap().len(), 2);
    let h1 = fx.db.list_allow_urls(Some("h1")).await.unwrap();
    assert_eq!(h1.len(), 1);
    assert_eq!(h1[0].url_pattern, "/api/public");
    assert_eq!(h1[0].match_type, "prefix");

    assert!(fx.db.delete_allow_url(r1.id).await.unwrap());
    assert!(!fx.db.delete_allow_url(r1.id).await.unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn block_url_lifecycle() {
    let fx = start_postgres().await;

    let r1 = fx
        .db
        .create_block_url(CreateUrlRule {
            host_code: "h1".into(),
            url_pattern: "/admin".into(),
            match_type: "prefix".into(),
            remarks: None,
        })
        .await
        .unwrap();
    let _ = fx
        .db
        .create_block_url(CreateUrlRule {
            host_code: "h2".into(),
            url_pattern: r".*\.env$".into(),
            match_type: "regex".into(),
            remarks: Some("dotenv leak".into()),
        })
        .await
        .unwrap();

    assert_eq!(fx.db.list_block_urls(None).await.unwrap().len(), 2);
    let h2 = fx.db.list_block_urls(Some("h2")).await.unwrap();
    assert_eq!(h2.len(), 1);
    assert_eq!(h2[0].match_type, "regex");

    assert!(fx.db.delete_block_url(r1.id).await.unwrap());
    assert!(!fx.db.delete_block_url(uuid::Uuid::new_v4()).await.unwrap());
}
