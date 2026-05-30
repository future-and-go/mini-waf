//! Shared engine fixture for Phase 07 integration tests.
//!
//! Spins a Postgres testcontainer and constructs a default `WafEngine`
//! backed by it. Each integration-test file gets its own container for
//! safe parallel `cargo test` execution. Cold-start ~3-5s.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use testcontainers::{ContainerAsync, ImageExt, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres as PostgresImage;
use waf_common::{HostConfig, RequestCtx};
use waf_engine::{WafEngine, WafEngineConfig};
use waf_storage::Database;

pub struct EngineFixture {
    pub db: Arc<Database>,
    pub engine: WafEngine,
    _container: ContainerAsync<PostgresImage>,
}

pub async fn start_engine() -> EngineFixture {
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
    let engine = WafEngine::new(Arc::clone(&db), WafEngineConfig::default());
    EngineFixture {
        db,
        engine,
        _container: container,
    }
}

/// Build a minimal `RequestCtx` with overrideable host code, path and IP.
pub fn make_ctx(host_code: &str, path: &str, ip: &str) -> RequestCtx {
    let host_config = Arc::new(HostConfig {
        code: host_code.into(),
        host: "example.com".into(),
        ..HostConfig::default()
    });
    RequestCtx {
        req_id: "fx".into(),
        client_ip: ip.parse::<IpAddr>().expect("ip parse"),
        client_port: 12345,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: path.into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}
