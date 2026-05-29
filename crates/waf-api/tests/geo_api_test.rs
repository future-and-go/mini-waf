//! Integration tests for the geo restriction API.

#![allow(
    dead_code,
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::undocumented_unsafe_blocks
)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::serve;
use gateway::{HostRouter, ResponseCache};
use serde_json::json;
use tempfile::TempDir;
use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use tokio::task::JoinHandle;
use waf_api::AppState;
use waf_api::auth::generate_access_token;
use waf_api::server::build_router;
use waf_engine::{WafEngine, WafEngineConfig};
use waf_storage::Database;

struct LocalServer {
    addr: SocketAddr,
    admin_token: String,
    viewer_token: String,
    tmp: TempDir,
    server_task: Option<JoinHandle<()>>,
    _container: ContainerAsync<PostgresImage>,
}

impl Drop for LocalServer {
    fn drop(&mut self) {
        if let Some(t) = self.server_task.take() {
            t.abort();
        }
    }
}

async fn start_local_server() -> LocalServer {
    unsafe {
        std::env::set_var("JWT_SECRET", "integration-test-secret-key-32bytes-min");
        std::env::set_var("MASTER_KEY", "integration-test-master-key-32bytes-min");
    }

    let container = PostgresImage::default()
        .with_tag("16-alpine")
        .start()
        .await
        .expect("start postgres testcontainer");
    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");
    let db_url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let db = Database::connect(&db_url, 5).await.expect("db connect");
    db.migrate().await.expect("migrate");
    let db = Arc::new(db);

    let tmp = tempfile::tempdir().expect("tempdir");
    let configs_dir = tmp.path().join("configs");
    std::fs::create_dir_all(&configs_dir).expect("mk configs");
    let main_cfg = configs_dir.join("default.toml");
    std::fs::write(&main_cfg, b"").expect("seed main config");

    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    let router = Arc::new(HostRouter::new());
    let cache = ResponseCache::new(8, 60, 300);
    let mut state_inner = AppState::new(Arc::clone(&db), Arc::clone(&engine), router, cache).expect("AppState::new");
    state_inner.main_config_file = Some(main_cfg.to_string_lossy().into_owned());
    let state = Arc::new(state_inner);

    let admin_token =
        generate_access_token(uuid::Uuid::new_v4(), "admin", "admin", &state.jwt_secret).expect("admin token");
    let viewer_token =
        generate_access_token(uuid::Uuid::new_v4(), "viewer", "viewer", &state.jwt_secret).expect("viewer token");

    let app = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let server_task = tokio::spawn(async move {
        let _ = serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    LocalServer {
        addr,
        admin_token,
        viewer_token,
        tmp,
        server_task: Some(server_task),
        _container: container,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("client")
}

fn url(s: &LocalServer, path: &str) -> String {
    format!("http://{}{path}", s.addr)
}

async fn create_rule(s: &LocalServer, iso: &str, action: &str) -> String {
    let resp = client()
        .post(url(s, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": iso, "action": action }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    body["data"]["id"].as_str().expect("id").to_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn list_returns_empty_initially() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 0);
    assert_eq!(body["data"], json!([]));
}

#[tokio::test(flavor = "multi_thread")]
async fn create_then_list_returns_uuid_id() {
    let s = start_local_server().await;
    let id = create_rule(&s, "vn", "block").await;
    // UUID v4 strings are 36 chars with dashes.
    assert_eq!(id.len(), 36);
    assert!(id.contains('-'));

    let body: serde_json::Value = client()
        .get(url(&s, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["iso_code"], "VN");
    assert_eq!(body["data"][0]["action"], "block");
}

#[tokio::test(flavor = "multi_thread")]
async fn create_rejects_invalid_action() {
    let s = start_local_server().await;
    let resp = client()
        .post(url(&s, "/api/geo-rules"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "us", "action": "nuke" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .post(url(&s, "/api/geo-rules"))
        .bearer_auth(&s.viewer_token)
        .json(&json!({ "iso_code": "us", "action": "block" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_known_field_succeeds() {
    let s = start_local_server().await;
    let id = create_rule(&s, "us", "block").await;
    let resp = client()
        .patch(url(&s, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "enabled": false }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["enabled"], false);
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_rejects_unknown_key() {
    let s = start_local_server().await;
    let id = create_rule(&s, "us", "block").await;
    let resp = client()
        .patch(url(&s, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "iso_code": "CN" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_removes_rule_and_404s_on_repeat() {
    let s = start_local_server().await;
    let id = create_rule(&s, "us", "block").await;
    let first = client()
        .delete(url(&s, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(first.status(), 200);

    let again = client()
        .delete(url(&s, &format!("/api/geo-rules/{id}")))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(again.status(), 404);
}

#[tokio::test(flavor = "multi_thread")]
async fn lookup_returns_503_when_geoip_unloaded() {
    let s = start_local_server().await;
    let resp = client()
        .post(url(&s, "/api/geoip/lookup"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "ip": "8.8.8.8" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 503);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["status"], "geoip_unavailable");
    assert_eq!(body["data"]["ip"], "8.8.8.8");
}
