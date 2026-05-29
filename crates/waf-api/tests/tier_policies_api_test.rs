//! Integration tests for the tier-policies API.
//!
//! Each test spins a fresh Postgres testcontainer + AppState wired to a temp
//! working directory so YAML I/O is hermetic and the engine constructor sees a
//! real DB pool.

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
    let policy = |fail: &str, rps: i64, cache: &str| {
        json!({
            "fail_mode": fail,
            "ddos_threshold_rps": rps,
            "cache_policy": cache,
            "risk_thresholds": { "allow": 20, "challenge": 60, "block": 85 }
        })
    };
    json!({
        "policies": {
            "critical":  policy("close", 50,   "no_cache"),
            "high":      policy("close", 200,  "default"),
            "medium":    policy("open",  500,  "short_ttl"),
            "catch_all": policy("open",  1000, "aggressive")
        },
        "classifier_rules": []
    })
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn get_returns_default_when_no_file() {
    let s = start_local_server().await;
    let body: serde_json::Value = client()
        .get(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(body["success"], true);
    assert!(body["data"]["policies"]["critical"].is_object());
    assert_eq!(body["data"]["policies"]["catch_all"]["ddos_threshold_rps"], 1000);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_round_trips_and_persists_to_disk() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["policies"]["medium"]["ddos_threshold_rps"] = json!(777);

    let put = client()
        .put(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let yaml = std::fs::read_to_string(s.tmp.path().join("configs/tier-policies.yaml")).expect("read yaml");
    assert!(yaml.contains("ddos_threshold_rps: 777"));

    let got: serde_json::Value = client()
        .get(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(got["data"]["policies"]["medium"]["ddos_threshold_rps"], 777);
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_inverted_thresholds() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["policies"]["high"]["risk_thresholds"]["allow"] = json!(95);
    body["policies"]["high"]["risk_thresholds"]["challenge"] = json!(60);
    body["policies"]["high"]["risk_thresholds"]["block"] = json!(85);

    let resp = client()
        .put(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);
    let err: serde_json::Value = resp.json().await.expect("json");
    assert!(err["error"].as_str().unwrap().contains("allow < challenge < block"));
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_missing_tier() {
    let s = start_local_server().await;
    let mut body = valid_body();
    body["policies"].as_object_mut().unwrap().remove("medium");

    let resp = client()
        .put(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    let status = resp.status().as_u16();
    assert!(status == 400 || status == 422, "got {status}");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_requires_admin_role() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.viewer_token)
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}

#[tokio::test(flavor = "multi_thread")]
async fn dry_run_matches_classifier_then_falls_back() {
    let s = start_local_server().await;

    let mut body = valid_body();
    body["classifier_rules"] = json!([
        { "id": 1, "priority": 10, "tier": "critical", "methods": ["POST"], "path_match": "/api/" },
        { "id": 2, "priority": 5,  "tier": "high",     "methods": ["GET"],  "path_match": "/" }
    ]);
    let put = client()
        .put(url(&s, "/api/tier-policies"))
        .bearer_auth(&s.admin_token)
        .json(&body)
        .send()
        .await
        .expect("send");
    assert_eq!(put.status(), 200);

    let v: serde_json::Value = client()
        .post(url(&s, "/api/tier-policies/dry-run"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "method": "POST", "path": "/api/foo" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(v["data"]["matched_tier"], "critical");
    assert_eq!(v["data"]["matched_rule_id"], 1);

    let v: serde_json::Value = client()
        .post(url(&s, "/api/tier-policies/dry-run"))
        .bearer_auth(&s.admin_token)
        .json(&json!({ "method": "DELETE", "path": "/something" }))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    assert_eq!(v["data"]["matched_tier"], "catch_all");
}

#[tokio::test(flavor = "multi_thread")]
async fn put_rejects_missing_bearer_token() {
    let s = start_local_server().await;
    let resp = client()
        .put(url(&s, "/api/tier-policies"))
        .json(&valid_body())
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401);
}
