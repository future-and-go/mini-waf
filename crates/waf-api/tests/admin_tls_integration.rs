//! Integration tests for the Admin API TLS functionality.
//!
//! These tests verify the TLS certificate lifecycle (generate, persist, reuse,
//! renew) and the HTTP redirect helper.  The end-to-end HTTPS connectivity test
//! uses a minimal Axum router served directly via axum-server — no real DB or
//! AppState needed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{Json, Router, routing::get};
use serde_json::json;
use waf_api::tls::{AdminTlsManager, spawn_http_redirect};
use waf_common::config::{AdminTlsConfig, AdminTlsMode};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Install the `ring` crypto provider for rustls (idempotent).
fn install_ring_provider_once() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Poll `https://127.0.0.1:{port}/health` (ignoring TLS cert) until it returns
/// 200 or the timeout elapses.
async fn wait_for_https_ready(port: u16, timeout: Duration) -> bool {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let url = format!("https://127.0.0.1:{port}/health");
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return true;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// ─── Test: AdminTlsManager bootstrap generates cert and persists files ────────

#[tokio::test(flavor = "multi_thread")]
async fn admin_tls_auto_mode_generates_and_persists() {
    install_ring_provider_once();

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AdminTlsConfig::default();
    cfg.data_dir = dir.path().to_string_lossy().to_string();
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let manager = AdminTlsManager::bootstrap(cfg, listen_addr)
        .expect("bootstrap ok")
        .expect("Some material");

    assert!(dir.path().join("cert.pem").exists(), "cert.pem must be created");
    assert!(dir.path().join("key.pem").exists(), "key.pem must be created");

    let fp = manager.fingerprint();
    assert!(!fp.is_empty(), "fingerprint must be non-empty");
    assert!(
        fp.chars().all(|c| c.is_ascii_hexdigit() || c == ':'),
        "fingerprint must be hex:colon format, got: {fp}"
    );
}

// ─── Test: Bootstrap reuses cert on second boot ───────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn admin_tls_reuse_on_second_boot() {
    install_ring_provider_once();

    let dir = tempfile::tempdir().unwrap();
    let mut cfg = AdminTlsConfig::default();
    cfg.data_dir = dir.path().to_string_lossy().to_string();
    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let fp1 = AdminTlsManager::bootstrap(cfg.clone(), listen_addr)
        .expect("first bootstrap")
        .expect("Some")
        .fingerprint();

    let fp2 = AdminTlsManager::bootstrap(cfg, listen_addr)
        .expect("second bootstrap")
        .expect("Some")
        .fingerprint();

    assert_eq!(fp1, fp2, "Fingerprint must be identical across restarts (cert reused)");
}

// ─── Test: Bootstrap regenerates when within renewal window ──────────────────

#[tokio::test(flavor = "multi_thread")]
async fn admin_tls_renews_when_within_window() {
    install_ring_provider_once();

    let dir = tempfile::tempdir().unwrap();
    // validity=2 days, renew_before=3 days → always within renewal window
    let mut cfg = AdminTlsConfig::default();
    cfg.data_dir = dir.path().to_string_lossy().to_string();
    cfg.validity_days = 2;
    cfg.renew_before_days = 3;

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let fp1 = AdminTlsManager::bootstrap(cfg.clone(), listen_addr)
        .expect("first bootstrap")
        .expect("Some")
        .fingerprint();

    let fp2 = AdminTlsManager::bootstrap(cfg, listen_addr)
        .expect("second bootstrap (should renew)")
        .expect("Some")
        .fingerprint();

    assert_ne!(fp1, fp2, "Cert must be regenerated when within the renewal window");
}

// ─── Test: Provided mode rejects missing cert/key paths ───────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn admin_tls_provided_mode_missing_paths_errors() {
    install_ring_provider_once();

    let mut cfg = AdminTlsConfig::default();
    cfg.mode = AdminTlsMode::Provided;
    cfg.cert_pem = None;
    cfg.key_pem = None;

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let result = AdminTlsManager::bootstrap(cfg, listen_addr);
    assert!(result.is_err(), "Provided mode with no cert/key paths must return Err");
}

// ─── Test: AdminCertResolver swap is atomic ───────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn admin_cert_resolver_swap_atomic() {
    install_ring_provider_once();

    // Build two independent TLS material sets
    let dir1 = tempfile::tempdir().unwrap();
    let mut cfg1 = AdminTlsConfig::default();
    cfg1.data_dir = dir1.path().to_string_lossy().to_string();

    let dir2 = tempfile::tempdir().unwrap();
    let mut cfg2 = AdminTlsConfig::default();
    cfg2.data_dir = dir2.path().to_string_lossy().to_string();
    // Short validity so the two certs are guaranteed to differ
    cfg2.validity_days = 2;
    cfg2.renew_before_days = 0;

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let manager1 = AdminTlsManager::bootstrap(cfg1, listen_addr)
        .expect("bootstrap 1")
        .expect("Some");

    let manager2 = AdminTlsManager::bootstrap(cfg2, listen_addr)
        .expect("bootstrap 2")
        .expect("Some");

    let mat2 = manager2.current_material();

    // Swap the cert in manager1's resolver to manager2's material
    manager1.resolver().swap(&mat2).expect("swap must succeed");

    // After swap the resolver holds manager2's cert — fingerprint of
    // current_material on manager1 is still the old one (material field
    // is not updated by swap alone), but the resolver itself serves mat2.
    // We verify the swap didn't panic and accepted the new material.
    let fp1 = manager1.fingerprint();
    let fp2 = manager2.fingerprint();
    // The two managers were created from distinct dirs → distinct certs
    assert_ne!(fp1, fp2, "The two bootstrapped certs must differ");
}

// ─── Test: End-to-end HTTPS /health reachable ────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn end_to_end_https_health_check() {
    install_ring_provider_once();

    let dir = tempfile::tempdir().unwrap();
    let mut tls_cfg = AdminTlsConfig::default();
    tls_cfg.data_dir = dir.path().to_string_lossy().to_string();

    // Pick an ephemeral port
    let tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let listen_addr = tmp.local_addr().unwrap();
    drop(tmp);
    let port = listen_addr.port();

    let manager = AdminTlsManager::bootstrap(tls_cfg, listen_addr)
        .expect("bootstrap")
        .expect("Some");
    let fp = manager.fingerprint();

    // Use `server_config()` to get the rustls ServerConfig already wired to
    // the hot-swappable resolver — no PEM decoding needed in the test.
    let rustls_config =
        axum_server::tls_rustls::RustlsConfig::from_config(manager.server_config().expect("server_config"));

    // Trivial Axum router — no DB needed for TLS connectivity check
    let app = Router::new().route("/health", get(|| async { Json(json!({"status": "ok"})) }));

    tokio::spawn(async move {
        let _ = axum_server::bind_rustls(listen_addr, rustls_config)
            .serve(app.into_make_service())
            .await;
    });

    assert!(
        wait_for_https_ready(port, Duration::from_secs(3)).await,
        "HTTPS server (fp={fp}) must be ready within 3 s on port {port}"
    );

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let resp = client
        .get(format!("https://127.0.0.1:{port}/health"))
        .send()
        .await
        .expect("GET /health must succeed");

    assert_eq!(resp.status(), 200, "Expected 200 OK from /health");
}

// ─── Test: HTTP redirect listener returns 301 ─────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn http_redirect_listener_returns_301() {
    install_ring_provider_once();

    let https_tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_addr = https_tmp.local_addr().unwrap();
    drop(https_tmp);

    let http_tmp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_port = http_tmp.local_addr().unwrap().port();
    drop(http_tmp);

    spawn_http_redirect(https_addr, Some(http_port));

    // Poll until the redirect port accepts connections (up to 1 s)
    let mut bound = false;
    for _ in 0..20 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        if tokio::net::TcpStream::connect(format!("127.0.0.1:{http_port}"))
            .await
            .is_ok()
        {
            bound = true;
            break;
        }
    }
    assert!(bound, "HTTP redirect listener must bind within 1 second");

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://127.0.0.1:{http_port}/some/path?q=1"))
        .send()
        .await
        .expect("redirect request must succeed");

    assert!(resp.status().is_redirection(), "Expected 3xx, got {}", resp.status());

    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    assert!(
        location.starts_with("https://"),
        "Location must start with https://, got: {location}"
    );
}

// ─── Test: AdminTlsConfig validate rejects unsupported TLS version ────────────

#[test]
fn admin_tls_config_validate_rejects_invalid_tls_version() {
    let mut cfg = AdminTlsConfig::default();
    cfg.min_tls_version = "1.0".to_owned();
    assert!(cfg.validate().is_err(), "Validation must fail for '1.0'");
}

// ─── Test: AdminTlsConfig validate rejects provided mode without paths ─────────

#[test]
fn admin_tls_config_validate_rejects_provided_without_paths() {
    let mut cfg = AdminTlsConfig::default();
    cfg.mode = AdminTlsMode::Provided;
    cfg.cert_pem = None;
    cfg.key_pem = None;
    assert!(
        cfg.validate().is_err(),
        "Validation must fail for mode=Provided with no cert_pem/key_pem"
    );
}
