//! Additional unit coverage for `gateway::ssl` helpers that don't need a
//! live `Database` pool. The ACME / DB I/O paths in `SslManager::*` are
//! intentionally NOT covered here: they require either a real PostgreSQL
//! pool (no `Database::mock()` seam exists) or live Let's Encrypt traffic.
//! See the dev-2 report at plans/reports/dev-2-260509-2129-ssl-and-waf-response.md
//! for the full uncovered-path inventory.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::doc_markdown
)]

use std::sync::Arc;

use gateway::SslManager;
use gateway::ssl::{CertInfo, ChallengeStore};

// ── ChallengeStore additional edge cases ────────────────────────────────────

#[test]
fn challenge_store_new_and_default_are_equivalent_observably() {
    // Both constructors should produce empty stores.
    let a = ChallengeStore::new();
    let b = ChallengeStore::default();
    assert!(a.get("any").is_none());
    assert!(b.get("any").is_none());
    a.set("k".into(), "v".into());
    // Independence: setting on `a` does not affect `b`.
    assert!(b.get("k").is_none());
    assert_eq!(a.get("k"), Some("v".into()));
}

#[test]
fn challenge_store_supports_many_concurrent_tokens() {
    let store = Arc::new(ChallengeStore::new());
    // Sequentially insert a batch and assert all readable.
    for i in 0..32 {
        store.set(format!("token-{i}"), format!("auth-{i}"));
    }
    for i in 0..32 {
        assert_eq!(store.get(&format!("token-{i}")), Some(format!("auth-{i}")));
    }
    for i in 0..32 {
        store.remove(&format!("token-{i}"));
    }
    for i in 0..32 {
        assert!(store.get(&format!("token-{i}")).is_none());
    }
}

#[test]
fn challenge_store_handles_empty_strings() {
    let store = ChallengeStore::new();
    store.set(String::new(), "auth".into());
    assert_eq!(store.get(""), Some("auth".into()));
    store.set("token".into(), String::new());
    assert_eq!(store.get("token"), Some(String::new()));
    store.remove("");
    assert!(store.get("").is_none());
}

// ── self-signed certificate edge cases ──────────────────────────────────────

#[test]
fn self_signed_pem_contains_pkcs8_private_key_marker() {
    let (_cert, key) = SslManager::generate_self_signed("rust.example.org").expect("ok");
    // rcgen emits PKCS8 private keys in modern versions.
    assert!(
        key.contains("PRIVATE KEY"),
        "expected a PKCS8 / SEC1 private key marker in PEM, got: {key}"
    );
}

#[test]
fn self_signed_cert_has_balanced_begin_end_markers() {
    let (cert, key) = SslManager::generate_self_signed("balanced.example.com").expect("ok");
    assert_eq!(cert.matches("BEGIN CERTIFICATE").count(), 1);
    assert_eq!(cert.matches("END CERTIFICATE").count(), 1);
    assert_eq!(key.matches("BEGIN").count(), 1);
    assert_eq!(key.matches("END").count(), 1);
}

#[test]
fn self_signed_handles_punycode_idn_domain() {
    // Pre-encoded IDN. rcgen should accept this as a regular DNS name.
    let (cert, _key) = SslManager::generate_self_signed("xn--bcher-kva.example").expect("idn");
    assert!(cert.contains("BEGIN CERTIFICATE"));
}

#[test]
fn self_signed_handles_wildcard_domain() {
    let (cert, _key) = SslManager::generate_self_signed("*.example.com").expect("wildcard");
    assert!(cert.contains("BEGIN CERTIFICATE"));
}

// ── CertInfo struct constructor smoke ───────────────────────────────────────

#[test]
fn cert_info_struct_is_constructible_and_clone() {
    let now = chrono::Utc::now();
    let info = CertInfo {
        cert_pem: "PEM-CERT".into(),
        key_pem: "PEM-KEY".into(),
        chain_pem: Some("PEM-CHAIN".into()),
        not_before: now,
        not_after: now + chrono::Duration::days(90),
        subject: "CN=test.example.com".into(),
        issuer: "Test CA".into(),
    };
    let cloned = info.clone();
    assert_eq!(cloned.cert_pem, "PEM-CERT");
    assert_eq!(cloned.subject, "CN=test.example.com");
    assert_eq!(cloned.chain_pem.as_deref(), Some("PEM-CHAIN"));
    // Debug impl present (smoke).
    let dbg = format!("{cloned:?}");
    assert!(dbg.contains("CertInfo"));
}

#[test]
fn cert_info_with_no_chain_round_trips() {
    let now = chrono::Utc::now();
    let info = CertInfo {
        cert_pem: "C".into(),
        key_pem: "K".into(),
        chain_pem: None,
        not_before: now,
        not_after: now,
        subject: "S".into(),
        issuer: "I".into(),
    };
    assert!(info.chain_pem.is_none());
}
