// admin_users + refresh_tokens coverage.
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use chrono::Duration;
use common::start_postgres;
use waf_storage::models::CreateAdminUser;

#[tokio::test(flavor = "multi_thread")]
async fn admin_user_create_get_list_count_login() {
    let fx = start_postgres().await;
    assert_eq!(fx.db.admin_users_count().await.unwrap(), 0);

    let user = fx
        .db
        .create_admin_user(
            CreateAdminUser {
                username: "alice".into(),
                email: Some("alice@example.com".into()),
                password: "ignored".into(),
                role: Some("admin".into()),
            },
            "hash:abc",
        )
        .await
        .unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.password_hash, "hash:abc");
    assert!(user.is_active);

    assert_eq!(fx.db.admin_users_count().await.unwrap(), 1);

    let by_id = fx.db.get_admin_user_by_id(user.id).await.unwrap().unwrap();
    assert_eq!(by_id.id, user.id);

    let by_name = fx.db.get_admin_user_by_username("alice").await.unwrap().unwrap();
    assert_eq!(by_name.id, user.id);

    let none = fx.db.get_admin_user_by_username("ghost").await.unwrap();
    assert!(none.is_none());

    let listed = fx.db.list_admin_users().await.unwrap();
    assert_eq!(listed.len(), 1);

    fx.db.update_admin_user_last_login(user.id).await.unwrap();
    let after = fx.db.get_admin_user_by_id(user.id).await.unwrap().unwrap();
    assert!(after.last_login.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn admin_user_unique_username_violation() {
    let fx = start_postgres().await;
    fx.db
        .create_admin_user(
            CreateAdminUser {
                username: "dup".into(),
                email: None,
                password: "x".into(),
                role: None,
            },
            "h1",
        )
        .await
        .unwrap();
    let res = fx
        .db
        .create_admin_user(
            CreateAdminUser {
                username: "dup".into(),
                email: None,
                password: "y".into(),
                role: None,
            },
            "h2",
        )
        .await;
    assert!(res.is_err(), "duplicate username must violate UNIQUE");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_token_create_lookup_revoke() {
    let fx = start_postgres().await;
    let user = fx
        .db
        .create_admin_user(
            CreateAdminUser {
                username: "bob".into(),
                email: None,
                password: "x".into(),
                role: None,
            },
            "h",
        )
        .await
        .unwrap();

    let expires = chrono::Utc::now() + Duration::hours(1);
    let token = fx
        .db
        .create_refresh_token(user.id, "tok-hash-1", expires)
        .await
        .unwrap();
    assert_eq!(token.user_id, user.id);
    assert!(!token.revoked);

    let lookup = fx.db.get_refresh_token_by_hash("tok-hash-1").await.unwrap().unwrap();
    assert_eq!(lookup.id, token.id);

    fx.db.revoke_refresh_token("tok-hash-1").await.unwrap();
    let after = fx.db.get_refresh_token_by_hash("tok-hash-1").await.unwrap();
    assert!(after.is_none(), "revoked tokens are filtered out");
}

#[tokio::test(flavor = "multi_thread")]
async fn refresh_token_expired_is_filtered() {
    let fx = start_postgres().await;
    let user = fx
        .db
        .create_admin_user(
            CreateAdminUser {
                username: "carol".into(),
                email: None,
                password: "x".into(),
                role: None,
            },
            "h",
        )
        .await
        .unwrap();
    let past = chrono::Utc::now() - Duration::hours(1);
    fx.db.create_refresh_token(user.id, "old-tok", past).await.unwrap();
    let res = fx.db.get_refresh_token_by_hash("old-tok").await.unwrap();
    assert!(res.is_none(), "expired tokens are filtered out");
}

#[tokio::test(flavor = "multi_thread")]
async fn revoke_all_user_tokens_revokes_every_token_for_that_user() {
    let fx = start_postgres().await;
    let user = fx
        .db
        .create_admin_user(
            CreateAdminUser {
                username: "dan".into(),
                email: None,
                password: "x".into(),
                role: None,
            },
            "h",
        )
        .await
        .unwrap();
    let exp = chrono::Utc::now() + Duration::hours(1);
    fx.db.create_refresh_token(user.id, "t1", exp).await.unwrap();
    fx.db.create_refresh_token(user.id, "t2", exp).await.unwrap();

    fx.db.revoke_all_user_tokens(user.id).await.unwrap();
    assert!(fx.db.get_refresh_token_by_hash("t1").await.unwrap().is_none());
    assert!(fx.db.get_refresh_token_by_hash("t2").await.unwrap().is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn get_admin_user_by_id_missing_returns_none() {
    let fx = start_postgres().await;
    let none = fx.db.get_admin_user_by_id(uuid::Uuid::new_v4()).await.unwrap();
    assert!(none.is_none());
}
