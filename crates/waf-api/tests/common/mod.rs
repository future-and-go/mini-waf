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
    // SAFETY: test-only; called before any other threads read these env vars.
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

    let app = build_router(Arc::clone(&state), false);
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
    // SAFETY: test-only; called before any other threads read these env vars.
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

    let app = build_router(Arc::clone(&state), false);
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

/// Variant that wires a real `cluster_state` (single-node) so cluster_*
/// handlers can exercise their populated branches.
pub async fn start_test_server_with_cluster() -> TestServer {
    use waf_cluster::{NodeState, StorageMode};
    use waf_common::config::ClusterConfig;

    // SAFETY: test-only; called before any other threads read these env vars.
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

    let cfg = ClusterConfig {
        enabled: true,
        node_id: "test-node".to_string(),
        role: "main".to_string(),
        listen_addr: "127.0.0.1:0".to_string(),
        ..Default::default()
    };
    let node_state = Arc::new(NodeState::new(cfg, StorageMode::Full).expect("node state"));
    // Seed a CA key so /api/cluster/token can succeed.
    *node_state.ca_key_pem.lock() = Some("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E0hK1MZmuuFQfbCYpV4i40K9OFDHIPEMd2K2\n-----END PRIVATE KEY-----\n".to_string());
    state_inner.cluster_state = Some(node_state);
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

    let app = build_router(Arc::clone(&state), false);
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

/// Variant that populates `crowdsec_cache` (and `crowdsec_lapi_url`) so the
/// active branches in /api/crowdsec/* are exercised.
pub async fn start_test_server_with_crowdsec() -> TestServer {
    use waf_engine::DecisionCache;

    // SAFETY: test-only; called before any other threads read these env vars.
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
    state_inner.crowdsec_cache = Some(Arc::new(DecisionCache::new(0)));
    state_inner.crowdsec_lapi_url = Some("http://127.0.0.1:18080".into());
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

    let app = build_router(Arc::clone(&state), false);
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

/// Variant that wires `victoria_logs_base_url` to a controllable mock HTTP
/// server so /api/v1/logs/* can hit the active branches.
pub async fn start_test_server_with_logs(vl_base: String) -> TestServer {
    // SAFETY: test-only; called before any other threads read these env vars.
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
    state_inner.victoria_logs_base_url = Some(vl_base);
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

    let app = build_router(Arc::clone(&state), false);
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

/// Host code used by [`seed_one_of_each`] and shared across stats integration
/// tests. Tests that filter by host_code (`?host_code=h1`) MUST use this
/// constant so a single rename here doesn't silently turn assertions into
/// no-ops.
pub const SEED_HOST_CODE: &str = "h1";

/// Seed one `attack_log` (action=block) + one `security_event` (action=block)
/// so every overview sub-query returns a non-trivial value.
pub async fn seed_one_of_each(db: &waf_storage::Database) {
    use uuid::Uuid;
    use waf_storage::models::{AttackLog, CreateSecurityEvent};

    let now = chrono::Utc::now();
    db.create_attack_log(AttackLog {
        id: Uuid::new_v4(),
        host_code: SEED_HOST_CODE.into(),
        host: "example.com".into(),
        client_ip: "10.0.0.1".into(),
        method: "GET".into(),
        path: "/seed".into(),
        query: None,
        rule_id: Some("SQLI-1".into()),
        rule_name: "sqli-seed".into(),
        action: "block".into(),
        phase: "request".into(),
        detail: None,
        request_headers: None,
        geo_info: None,
        created_at: now,
    })
    .await
    .expect("seed attack_log");

    db.create_security_event(CreateSecurityEvent {
        host_code: SEED_HOST_CODE.into(),
        client_ip: "10.0.0.2".into(),
        method: "POST".into(),
        path: "/seed".into(),
        rule_id: Some("XSS-1".into()),
        rule_name: "xss-seed".into(),
        action: "block".into(),
        detail: None,
        geo_info: None,
    })
    .await
    .expect("seed security_event");
}

/// Insert one `security_event` row with arbitrary host/path/rule/action.
/// Used by integration tests that need granular control over which rows
/// exist (e.g., to verify host_code or action filters partition results).
pub async fn insert_security_event(
    db: &waf_storage::Database,
    host: &str,
    path: &str,
    rule_id: Option<&str>,
    rule_name: &str,
    action: &str,
) {
    use waf_storage::models::CreateSecurityEvent;
    db.create_security_event(CreateSecurityEvent {
        host_code: host.into(),
        client_ip: "127.0.0.1".into(),
        method: "GET".into(),
        path: path.into(),
        rule_id: rule_id.map(str::to_string),
        rule_name: rule_name.into(),
        action: action.into(),
        detail: None,
        geo_info: None,
    })
    .await
    .expect("insert_security_event");
}

/// GET `path` with the server's admin token and return the parsed JSON body.
pub async fn fetch(s: &TestServer, path: &str) -> serde_json::Value {
    client()
        .get(url_for(s.addr, path))
        .bearer_auth(&s.admin_token)
        .send()
        .await
        .expect("fetch send")
        .json()
        .await
        .expect("fetch json")
}
