//! Integration tests for the relay & proxy intel API.

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

fn valid_relay_body() -> serde_json::Value {
    json!({
        "enabled": true,
        "providers": {
            "asn_classifier": { "enabled": true, "risk_weight": 15 },
            "tor_exit": { "enabled": true, "risk_weight": 30 },
            "datacenter": { "enabled": true, "risk_weight": 15 },
            "proxy_chain": { "enabled": true, "risk_weight": 20 },
            "xff_validator": { "enabled": true, "risk_weight": 10, "max_chain_depth": 3, "reject_private_in_chain": true }
        },
        "intel": {
            "asn_feed": { "url": "https://example.test/asn", "refresh_secs": 86400 },
            "tor_feed": { "url": "https://example.test/tor", "refresh_secs": 3600 },
            "datacenter_set": { "path": "" }
        },
        "trusted_proxies": ["10.0.0.0/8"],
        "risk_weights": { "tor": 35, "datacenter": 15, "bad_asn": 25 }
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], false);
    assert_eq!(body["data"]["providers"]["tor_exit"]["enabled"], true);
    assert_eq!(body["data"]["risk_weights"]["tor"], 30);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_via_get() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_relay_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url(&s, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["risk_weights"]["tor"], 35);
    assert_eq!(body["data"]["trusted_proxies"][0], "10.0.0.0/8");

    let yaml = std::fs::read_to_string(s.tmp.path().join("configs/relay.yaml")).expect("read yaml");
    assert!(yaml.contains("tor_exit"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/relay/config"))
        .bearer_auth(&s.viewer_token)
        .json(&valid_relay_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn intel_status_reflects_configured_urls() {
    let s = start_local_server().await;
    let put = client()
        .put(url(&s, "/api/relay/config"))
        .bearer_auth(&s.admin_token)
        .json(&valid_relay_body())
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let body: serde_json::Value = client()
        .get(url(&s, "/api/relay/intel/status"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["tor"]["configured_url"], "https://example.test/tor");
    assert_eq!(body["data"]["asn"]["configured_url"], "https://example.test/asn");
}

#[tokio::test(flavor = "multi_thread")]
async fn intel_refresh_validates_yaml_then_succeeds() {
    let s = start_local_server().await;
    // Seed minimal valid YAML that the engine loader accepts.
    let yaml = "enabled: false\n";
    std::fs::write(s.tmp.path().join("configs/relay.yaml"), yaml).expect("seed yaml");

    let resp = client()
        .post(url(&s, "/api/relay/intel/refresh"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(body["data"]["parsed"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_evaluates_against_real_detector() {
    let s = start_local_server().await;
    let yaml = "enabled: false\n";
    std::fs::write(s.tmp.path().join("configs/relay.yaml"), yaml).expect("seed yaml");

    let body: serde_json::Value = client()
        .post(url(&s, "/api/relay/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "client_ip": "203.0.113.5", "xff": "203.0.113.5" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    // Empty provider registry → verdicts empty but real_ip should be returned.
    assert_eq!(body["data"]["client_ip"], "203.0.113.5");
    assert!(body["data"]["verdicts"].is_array());
    assert!(body["data"]["real_ip"].is_string());
}

#[tokio::test(flavor = "multi_thread")]
async fn test_relay_rejects_bad_ip() {
    let s = start_local_server().await;
    let yaml = "enabled: false\n";
    std::fs::write(s.tmp.path().join("configs/relay.yaml"), yaml).expect("seed yaml");

    let resp = client()
        .post(url(&s, "/api/relay/test"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "client_ip": "not-an-ip" }))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}
