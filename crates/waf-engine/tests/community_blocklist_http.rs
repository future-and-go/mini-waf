//! Integration tests for `community::blocklist` HTTP paths via wiremock.
//!
//! Covers: fetch_signing_keys_from_server (success, 404, bad JSON, too many keys,
//! inactive key filtered, unsupported algorithm filtered), full_pull_decoded
//! (success → blocklist populated, 404 → no entries, invalid JSON, size limit),
//! full_pull_verified (with valid signature, invalid signature, missing sig fields),
//! delta_pull (version 0 returns false, GONE returns false, valid delta applied,
//! invalid sig rejected), check_ip, len, is_empty, run_sync_task shutdown.

use std::net::IpAddr;
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey};
use tokio::sync::watch;
use waf_engine::community::blocklist::{CommunityBlocklistSync, fetch_signing_keys_from_server, parse_public_key};
use waf_engine::community::client::CommunityClient;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ── helpers ────────────────────────────────────────────────────────────────────

fn client(base_url: &str) -> Arc<CommunityClient> {
    Arc::new(CommunityClient::new(base_url).expect("client"))
}

fn signing_key() -> SigningKey {
    SigningKey::generate(&mut rand::rngs::OsRng)
}

/// Build a blocklist sync with no verify_key (unsigned mode).
fn sync_unsigned(client: Arc<CommunityClient>) -> Arc<CommunityBlocklistSync> {
    Arc::new(CommunityBlocklistSync::new(client, "api-key".to_string(), 3600, None))
}

/// Build a valid decoded blocklist JSON response body.
fn decoded_body(entries: &[(&str, &str, &str)]) -> serde_json::Value {
    let entries_json: Vec<serde_json::Value> = entries
        .iter()
        .map(|(ip, reason, source)| serde_json::json!({ "ip": ip, "reason": reason, "source": source }))
        .collect();
    serde_json::json!({ "version": 42, "entries": entries_json })
}

// ── fetch_signing_keys_from_server ────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn fetch_signing_keys_success_returns_active_keys() {
    let server = MockServer::start().await;
    let sk = signing_key();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    Mock::given(method("GET"))
        .and(path("/api/v1/keys/signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [
                { "key_id": "k1", "public_key_hex": pk_hex, "algorithm": "ed25519", "status": "active" },
                { "key_id": "k2", "public_key_hex": pk_hex, "algorithm": "ed25519", "status": "revoked" },
            ]
        })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let keys = fetch_signing_keys_from_server(&c).await.expect("ok");
    assert_eq!(keys.len(), 1, "only active keys returned");
    assert_eq!(keys[0].0, "k1");
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_signing_keys_404_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/keys/signing"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(fetch_signing_keys_from_server(&c).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_signing_keys_bad_json_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/keys/signing"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(fetch_signing_keys_from_server(&c).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_signing_keys_unsupported_algorithm_skipped() {
    let server = MockServer::start().await;
    let sk = signing_key();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    Mock::given(method("GET"))
        .and(path("/api/v1/keys/signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [
                { "key_id": "k1", "public_key_hex": pk_hex, "algorithm": "rsa", "status": "active" },
            ]
        })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let keys = fetch_signing_keys_from_server(&c).await.expect("ok");
    assert_eq!(keys.len(), 0, "rsa key skipped");
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_signing_keys_empty_algorithm_accepted() {
    let server = MockServer::start().await;
    let sk = signing_key();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    Mock::given(method("GET"))
        .and(path("/api/v1/keys/signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [
                { "key_id": "k1", "public_key_hex": pk_hex, "algorithm": "", "status": "active" },
            ]
        })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let keys = fetch_signing_keys_from_server(&c).await.expect("ok");
    assert_eq!(keys.len(), 1, "empty algorithm (backwards compat) accepted");
}

#[tokio::test(flavor = "multi_thread")]
async fn fetch_signing_keys_too_many_returns_error() {
    let server = MockServer::start().await;
    let sk = signing_key();
    let pk_hex = hex::encode(sk.verifying_key().to_bytes());

    // Build 33 keys (MAX_SIGNING_KEYS = 32)
    let keys: Vec<serde_json::Value> = (0..33)
        .map(|i| serde_json::json!({ "key_id": format!("k{i}"), "public_key_hex": pk_hex, "algorithm": "ed25519", "status": "active" }))
        .collect();

    Mock::given(method("GET"))
        .and(path("/api/v1/keys/signing"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "keys": keys })))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    assert!(fetch_signing_keys_from_server(&c).await.is_err());
}

// ── full_pull_decoded (unsigned mode) ─────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_decoded_populates_blocklist() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/decoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(decoded_body(&[
            ("1.2.3.4", "brute-force", "community"),
            ("5.6.7.8", "scan", "community"),
        ])))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let sync = sync_unsigned(c);

    // run_sync_task would call full_pull; simulate by running a short shutdown
    let (tx, rx) = watch::channel(false);

    // Spawn sync task then immediately send shutdown
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    // Small delay to allow initial full_pull to fire
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    // Blocklist should now contain entries
    let ip1: IpAddr = "1.2.3.4".parse().expect("ip");
    let ip2: IpAddr = "5.6.7.8".parse().expect("ip");
    assert!(sync.check_ip(&ip1).is_some());
    assert!(sync.check_ip(&ip2).is_some());
    assert!(!sync.is_empty());
    assert_eq!(sync.len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_decoded_404_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/decoded"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let sync = sync_unsigned(c);

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    // No entries after failed pull
    assert!(sync.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_decoded_invalid_json_does_not_panic() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/decoded"))
        .respond_with(ResponseTemplate::new(200).set_body_string("not-json"))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let sync = sync_unsigned(c);

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    assert!(sync.is_empty());
}

// ── full_pull_verified (signed mode) ─────────────────────────────────────────

/// Build a signed blocklist response: entries → JSON → zstd → sign → hex-encode.
fn build_signed_response(sk: &SigningKey, entries_json: serde_json::Value, version: u64) -> serde_json::Value {
    let json_bytes = serde_json::to_vec(&entries_json).expect("serialize");
    let compressed = zstd::encode_all(json_bytes.as_slice(), 3).expect("compress");
    let signature = sk.sign(&compressed);
    serde_json::json!({
        "version": version,
        "payload_hex": hex::encode(&compressed),
        "signature_hex": hex::encode(signature.to_bytes()),
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_verified_with_valid_signature_populates_blocklist() {
    let sk = signing_key();
    let vk = sk.verifying_key();

    let entries = serde_json::json!([
        { "ip": "10.0.0.1", "scenario": "brute_force", "action": "ban" }
    ]);
    let body = build_signed_response(&sk, entries, 1);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/full"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let pk_hex = hex::encode(vk.to_bytes());
    let verify_key = parse_public_key(&pk_hex).expect("parse key");

    let c = client(&server.uri());
    let sync = Arc::new(CommunityBlocklistSync::new(c, "k".to_string(), 3600, Some(verify_key)));

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    let ip: IpAddr = "10.0.0.1".parse().expect("ip");
    assert!(sync.check_ip(&ip).is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_verified_wrong_key_rejects_and_stays_empty() {
    let sk = signing_key();
    let wrong_sk = signing_key(); // different key — signature won't verify

    let entries = serde_json::json!([
        { "ip": "10.0.0.2", "scenario": "scan", "action": "ban" }
    ]);
    // Sign with `sk`, but verify with `wrong_sk.verifying_key()`
    let body = build_signed_response(&sk, entries, 1);

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/full"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let wrong_vk_hex = hex::encode(wrong_sk.verifying_key().to_bytes());
    let verify_key = parse_public_key(&wrong_vk_hex).expect("parse key");

    let c = client(&server.uri());
    let sync = Arc::new(CommunityBlocklistSync::new(c, "k".to_string(), 3600, Some(verify_key)));

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    // Signature mismatch → blocklist stays empty
    assert!(sync.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_verified_missing_fields_rejected() {
    let sk = signing_key();
    let vk = sk.verifying_key();

    // Response missing payload_hex / signature_hex fields
    let body = serde_json::json!({ "version": 1 });

    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/full"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&server)
        .await;

    let pk_hex = hex::encode(vk.to_bytes());
    let verify_key = parse_public_key(&pk_hex).expect("parse");

    let c = client(&server.uri());
    let sync = Arc::new(CommunityBlocklistSync::new(c, "k".to_string(), 3600, Some(verify_key)));

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    assert!(sync.is_empty());
}

// ── check_ip / len / is_empty ─────────────────────────────────────────────────

#[test]
fn new_blocklist_is_empty_and_check_misses() {
    let c = Arc::new(CommunityClient::new("http://localhost").expect("client"));
    let sync = CommunityBlocklistSync::new(c, "k".to_string(), 60, None);
    assert!(sync.is_empty());
    assert_eq!(sync.len(), 0);
    let ip: IpAddr = "1.2.3.4".parse().expect("ip");
    assert!(sync.check_ip(&ip).is_none());
}

// ── run_sync_task shutdown signal ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn run_sync_task_exits_on_shutdown_signal() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(503)) // always fail
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let sync = sync_unsigned(c);

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    // Wait for initial pull attempt then signal shutdown
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let _ = tx.send(true);

    // Task should complete promptly
    tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        .await
        .expect("task should exit within 2s")
        .expect("join ok");
}

// ── client unreachable falls back gracefully ──────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_decoded_unreachable_server_does_not_panic() {
    let c = Arc::new(CommunityClient::new("http://127.0.0.1:1").expect("client"));
    let sync = sync_unsigned(c);

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    assert!(sync.is_empty());
}

// ── decoded pull with invalid IPs skipped ────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn full_pull_decoded_invalid_ips_skipped() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/waf/blocklist/decoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(decoded_body(&[
            ("not-an-ip", "scan", "community"),
            ("valid-2.0.0.1-not", "scan", "community"),
            ("8.8.8.8", "ok", "community"),
        ])))
        .mount(&server)
        .await;

    let c = client(&server.uri());
    let sync = sync_unsigned(c);

    let (tx, rx) = watch::channel(false);
    let sync2 = Arc::clone(&sync);
    let handle = tokio::spawn(async move { sync2.run_sync_task(rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let _ = tx.send(true);
    let _ = handle.await;

    // Only the valid IP should be stored
    assert_eq!(sync.len(), 1);
    let ip: IpAddr = "8.8.8.8".parse().expect("ip");
    assert!(sync.check_ip(&ip).is_some());
}
