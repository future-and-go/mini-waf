//! Integration tests for the DDoS protection API.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::doc_markdown,
    clippy::undocumented_unsafe_blocks
)]

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
    state: Arc<AppState>,
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

    let admin_token = generate_access_token(
        uuid::Uuid::new_v4(),
        "admin",
        "admin",
        &state.jwt_secret,
    )
    .expect("admin token");
    let viewer_token = generate_access_token(
        uuid::Uuid::new_v4(),
        "viewer",
        "viewer",
        &state.jwt_secret,
    )
    .expect("viewer token");

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
        state,
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

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn valid_body() -> serde_json::Value {
    json!({
        "enabled": true,
        "per_ip": { "threshold_rps": 100, "window_secs": 10 },
        "per_fingerprint": { "threshold_rps": 200, "window_secs": 10 },
        "ban_durations_secs": [60, 300, 3600],
        "store": { "backend": "memory", "redis_url": "" }
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn config_get_returns_default_when_no_file() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/ddos/config"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["enabled"], true);
    assert_eq!(body["data"]["per_ip"]["threshold_rps"], 100);
}

#[tokio::test(flavor = "multi_thread")]
async fn config_put_round_trips_to_disk() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["per_ip"]["threshold_rps"] = json!(555);

    let put = client()
        .put(url(&s, "/api/ddos/config"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let yaml = std::fs::read_to_string(s.tmp.path().join("configs/ddos.yaml")).expect("read yaml");
    assert!(yaml.contains("threshold_rps: 555"));
}

#[tokio::test(flavor = "multi_thread")]
async fn config_put_rejects_empty_ban_durations() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["ban_durations_secs"] = json!([]);

    let resp = client()
        .put(url(&s, "/api/ddos/config"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn config_put_rejects_non_positive_threshold() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["per_ip"]["threshold_rps"] = json!(0);
    let resp = client()
        .put(url(&s, "/api/ddos/config"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn config_put_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/ddos/config"))
        .bearer_auth(&s.viewer_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn ban_table_lists_empty_when_no_bans() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/ddos/ban-table"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"].as_array().map(Vec::len), Some(0));
    assert_eq!(body["total"], 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn ban_table_returns_live_entries_after_manual_insert() {
    let s = start_local_server().await;
    let ip: IpAddr = "10.20.30.40".parse().unwrap();
    s.state.engine.ddos_ban_table().insert(ip, now_ms() + 60_000);

    let body: serde_json::Value = client()
        .get(url(&s, "/api/ddos/ban-table"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["total"], 1);
    assert_eq!(body["data"][0]["ip"], "10.20.30.40");
    assert!(body["data"][0]["ttl_remaining_secs"].as_i64().unwrap() > 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_ban_entry_rejects_invalid_ip() {
    let s = start_local_server().await;
    let resp = client()
        .delete(url(&s, "/api/ddos/ban-table/not-an-ip"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_ban_entry_unknown_ip_returns_not_removed() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .delete(url(&s, "/api/ddos/ban-table/1.2.3.4"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["removed"], false);
    assert_eq!(body["data"]["ip"], "1.2.3.4");
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_ban_entry_removes_live_ban() {
    let s = start_local_server().await;
    let ip: IpAddr = "9.9.9.9".parse().unwrap();
    s.state.engine.ddos_ban_table().insert(ip, now_ms() + 60_000);
    assert!(s.state.engine.ddos_ban_table().contains(ip, now_ms()));

    let body: serde_json::Value = client()
        .delete(url(&s, "/api/ddos/ban-table/9.9.9.9"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["data"]["removed"], true);
    assert!(!s.state.engine.ddos_ban_table().contains(ip, now_ms()));
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_ban_entry_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .delete(url(&s, "/api/ddos/ban-table/1.2.3.4"))
        .bearer_auth(&s.viewer_token)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn metrics_endpoint_returns_zero_counters_on_fresh_engine() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/ddos/metrics"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], true);
    assert_eq!(body["data"]["active_bans"], 0);
    assert_eq!(body["data"]["bans_total"], 0);
    assert_eq!(body["data"]["bursts_total"], 0);
}
