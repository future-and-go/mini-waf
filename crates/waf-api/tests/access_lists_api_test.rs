//! Integration tests for the access-lists API.

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
    let mut state_inner =
        AppState::new(Arc::clone(&db), Arc::clone(&engine), router, cache).expect("AppState::new");
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
        "version": 1,
        "dry_run": false,
        "ip_whitelist": ["1.2.3.4"],
        "ip_blacklist": ["9.9.9.9"],
        "host_whitelist": {
            "critical": ["admin.example.com"],
            "high": [],
            "medium": [],
            "catch_all": ["public.example.com"]
        },
        "tier_whitelist_mode": {
            "critical": "blacklist_only",
            "high": "blacklist_only",
            "medium": "full_bypass",
            "catch_all": "full_bypass"
        }
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["version"], 1);
    assert_eq!(body["data"]["dry_run"], false);
    assert_eq!(body["data"]["tier_whitelist_mode"]["medium"], "full_bypass");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_to_disk_under_configs_dir() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let yaml = std::fs::read_to_string(s.tmp.path().join("configs/access-lists.yaml")).expect("read yaml");
    assert!(yaml.contains("- 9.9.9.9"));
    assert!(yaml.contains("admin.example.com"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_unknown_tier_mode() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["tier_whitelist_mode"]["high"] = json!("garbage_mode");

    let resp = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.viewer_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_then_get_round_trip() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["ip_blacklist"][0], "9.9.9.9");
    assert_eq!(body["data"]["ip_whitelist"][0], "1.2.3.4");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_endpoint_blacklist_wins_over_whitelist() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["ip_whitelist"] = json!(["9.9.9.9"]);
    body["ip_blacklist"] = json!(["9.9.9.9"]);

    let put = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let v: serde_json::Value = client()
        .get(url(&s, "/api/access-lists/test?ip=9.9.9.9"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(v["data"]["verdict"], "block");
    assert_eq!(v["data"]["reason"], "ip_blacklist");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_endpoint_host_whitelist_full_bypass() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let v: serde_json::Value = client()
        .get(url(
            &s,
            "/api/access-lists/test?ip=8.8.8.8&host=public.example.com&tier=catch_all",
        ))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(v["data"]["verdict"], "bypass");
    assert_eq!(v["data"]["reason"], "host_whitelist");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_endpoint_no_match_passes() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/access-lists"))
        .bearer_auth(&s.admin_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let v: serde_json::Value = client()
        .get(url(&s, "/api/access-lists/test?ip=42.42.42.42&host=other.example.com&tier=medium"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(v["data"]["verdict"], "pass");
    assert_eq!(v["data"]["reason"], "no_match");
}
