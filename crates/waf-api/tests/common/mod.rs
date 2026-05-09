// Test fixture for waf-api integration tests.
//
// Spins a real Postgres container, builds the production Router with a real
// AppState (db + engine + router + cache), binds the server to a random
// loopback port, seeds an admin user, and returns:
//   - addr  : SocketAddr the server is listening on
//   - db    : shared Database handle (for direct DB seeding inside tests)
//   - admin_token  : valid JWT for the seeded admin
//   - admin_password : password the admin was seeded with (for /api/auth/login)
//
// On Drop the spawned axum::serve task is aborted and the container is torn
// down (sqlx pool drops first, then container — drop order matters).
//
// Per-file containers keep `cargo test` parallelism safe and prevent a
// crashing test from poisoning others.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::serve;
use gateway::{HostRouter, ResponseCache};
use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use tokio::task::JoinHandle;
use waf_api::AppState;
use waf_api::auth::{generate_access_token, hash_password};
use waf_api::server::build_router;
use waf_engine::{WafEngine, WafEngineConfig};
use waf_storage::Database;
use waf_storage::models::CreateAdminUser;

pub struct TestServer {
    pub addr: SocketAddr,
    pub db: Arc<Database>,
    pub admin_token: String,
    pub admin_password: String,
    pub admin_id: uuid::Uuid,
    pub state: Arc<AppState>,
    server_task: Option<JoinHandle<()>>,
    _container: ContainerAsync<PostgresImage>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(t) = self.server_task.take() {
            t.abort();
        }
    }
}

/// Spin a fresh testcontainer + production Router and bind on 127.0.0.1:0.
/// JWT_SECRET is forced for AppState construction. Admin user "admin" is
/// seeded with a deterministic-but-unique password per fixture.
pub async fn start_test_server() -> TestServer {
    // Force a JWT_SECRET so AppState::new succeeds. This env-var is process
    // wide; we set it once and let cargo-test parallelism reuse the value
    // (every fixture sets the same string).
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
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let db = Database::connect(&url, 5).await.expect("db connect");
    db.migrate().await.expect("migrate");
    let db = Arc::new(db);

    // Build production state with minimal real components.
    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    let router = Arc::new(HostRouter::new());
    let cache = ResponseCache::new(8, 60, 300);
    let state = Arc::new(
        AppState::new(Arc::clone(&db), Arc::clone(&engine), Arc::clone(&router), cache).expect("AppState::new"),
    );

    // Seed admin user with a known password.
    let admin_password = "test-admin-password".to_string();
    let hash = hash_password(&admin_password).expect("hash password");
    let admin = db
        .create_admin_user(
            CreateAdminUser {
                username: "admin".into(),
                email: Some("admin@example.com".into()),
                password: admin_password.clone(),
                role: Some("admin".into()),
            },
            &hash,
        )
        .await
        .expect("seed admin");

    let admin_token =
        generate_access_token(admin.id, &admin.username, &admin.role, &state.jwt_secret).expect("issue admin token");

    let app = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let server_task = tokio::spawn(async move {
        let _ = serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    TestServer {
        addr,
        db,
        admin_token,
        admin_password,
        admin_id: admin.id,
        state,
        server_task: Some(server_task),
        _container: container,
    }
}

/// Variant that wires `panel_config_path` to a writable temp file before
/// starting the server. Used by panel_api integration tests that need to
/// exercise the success branches of GET/PUT /api/panel-config.
pub async fn start_test_server_with_panel() -> (TestServer, std::path::PathBuf) {
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
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let db = Database::connect(&url, 5).await.expect("db connect");
    db.migrate().await.expect("migrate");
    let db = Arc::new(db);

    let engine = Arc::new(WafEngine::new(Arc::clone(&db), WafEngineConfig::default()));
    let router = Arc::new(HostRouter::new());
    let cache = ResponseCache::new(8, 60, 300);
    let mut state_inner =
        AppState::new(Arc::clone(&db), Arc::clone(&engine), Arc::clone(&router), cache).expect("AppState::new");

    let panel_path = std::env::temp_dir().join(format!("waf-panel-test-{}.toml", uuid::Uuid::new_v4()));
    // Seed an empty default panel config so GET succeeds.
    let default_cfg = waf_common::panel_config::WafPanelConfig::default();
    let default_toml = default_cfg.to_toml_string().expect("serialize default panel cfg");
    tokio::fs::write(&panel_path, default_toml.as_bytes())
        .await
        .expect("seed panel cfg");
    state_inner.panel_config_path = Some(panel_path.clone());
    let state = Arc::new(state_inner);

    let admin_password = "test-admin-password".to_string();
    let hash = hash_password(&admin_password).expect("hash password");
    let admin = db
        .create_admin_user(
            CreateAdminUser {
                username: "admin".into(),
                email: Some("admin@example.com".into()),
                password: admin_password.clone(),
                role: Some("admin".into()),
            },
            &hash,
        )
        .await
        .expect("seed admin");

    let admin_token =
        generate_access_token(admin.id, &admin.username, &admin.role, &state.jwt_secret).expect("issue admin token");

    let app = build_router(Arc::clone(&state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let server_task = tokio::spawn(async move {
        let _ = serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await;
    });

    let server = TestServer {
        addr,
        db,
        admin_token,
        admin_password,
        admin_id: admin.id,
        state,
        server_task: Some(server_task),
        _container: container,
    };
    (server, panel_path)
}

/// Build a base URL for the test server.
pub fn url_for(addr: SocketAddr, path: &str) -> String {
    format!("http://{addr}{path}")
}

/// Build a reqwest client with a short timeout so misroutes don't hang the
/// suite.
pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("build reqwest client")
}
