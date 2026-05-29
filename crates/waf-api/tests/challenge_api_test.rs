//! Integration tests for the challenge engine API.

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

fn valid_body() -> serde_json::Value {
    json!({
        "enabled": false,
        "challenge_type": "pow_challenge",
        "ttl_secs": 120,
        "cookie_name": "__cc",
        "cookie_max_age": 60,
        "same_site": "Lax",
        "http_only": true,
        "branding": { "title": "Verifying…", "message": "Hold on a moment." },
        "nonce_store": { "capacity": 2048, "gc_interval_secs": 30 }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["challenge_type"], "js_challenge");
    assert_eq!(body["data"]["cookie_name"], "__waf_cc");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_via_get() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url(&s, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["challenge_type"], "pow_challenge");
    assert_eq!(body["data"]["cookie_name"], "__cc");
    assert_eq!(body["data"]["branding"]["title"], "Verifying…");

    // Verify the YAML wrapper was written under the configured root.
    let yaml = std::fs::read_to_string(s.tmp.path().join("configs/challenge.yaml")).expect("read yaml");
    assert!(yaml.contains("challenge:"));
    assert!(yaml.contains("pow_challenge"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/challenge/config"))
        .bearer_auth(&s.viewer_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_malformed_body() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/challenge/config"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "enabled": true }))
        .send()
        .await
        .expect("send");
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test(flavor = "multi_thread")]
async fn preview_escapes_html_in_branding() {
    let s = start_local_server().await;
    let html = client()
        .post(url(&s, "/api/challenge/preview"))
        .bearer_auth(&s.admin_token)
        .json(&json!({
            "branding": {
                "title": "<script>alert('xss')</script>",
                "message": "& angle <brackets>"
            }
        }))
        .send()
        .await
        .expect("send")
        .text()
        .await
        .expect("text");
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;script&gt;"));
    assert!(html.contains("&amp; angle"));
}

#[tokio::test(flavor = "multi_thread")]
async fn stats_endpoint_returns_zero_counts() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/challenge/stats"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["issued"], 0);
    assert_eq!(body["data"]["passed"], 0);
}
