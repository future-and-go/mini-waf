//! Phase 05: SSL helpers that do not require a Database.

use gateway::SslManager;
use gateway::ssl::ChallengeStore;

#[test]
fn challenge_store_set_get_remove_round_trip() {
    let store = ChallengeStore::new();
    assert!(store.get("missing").is_none());
    store.set("token-a".into(), "key-auth-a".into());
    store.set("token-b".into(), "key-auth-b".into());
    assert_eq!(store.get("token-a"), Some("key-auth-a".into()));
    assert_eq!(store.get("token-b"), Some("key-auth-b".into()));
    store.remove("token-a");
    assert!(store.get("token-a").is_none());
    assert_eq!(store.get("token-b"), Some("key-auth-b".into()));
}

#[test]
fn challenge_store_default_is_empty() {
    let store = ChallengeStore::default();
    assert!(store.get("anything").is_none());
}

#[test]
fn challenge_store_overwrite_existing_token() {
    let store = ChallengeStore::new();
    store.set("t".into(), "v1".into());
    store.set("t".into(), "v2".into());
    assert_eq!(store.get("t"), Some("v2".into()));
}

#[test]
fn challenge_store_remove_missing_is_noop() {
    let store = ChallengeStore::new();
    store.remove("never-existed");
    assert!(store.get("never-existed").is_none());
}

#[test]
fn self_signed_generates_valid_pem_for_dns_name() {
    let (cert, key) = SslManager::generate_self_signed("example.com").expect("self-signed");
    assert!(cert.contains("BEGIN CERTIFICATE"));
    assert!(cert.contains("END CERTIFICATE"));
    assert!(key.contains("BEGIN"));
    assert!(key.contains("END"));
}

#[test]
fn self_signed_generates_unique_pairs_per_call() {
    let (cert1, key1) = SslManager::generate_self_signed("a.example.com").expect("first");
    let (cert2, key2) = SslManager::generate_self_signed("b.example.com").expect("second");
    assert_ne!(cert1, cert2, "distinct certs per call");
    assert_ne!(key1, key2, "distinct keys per call");
}

#[test]
fn self_signed_for_subdomain_succeeds() {
    let (cert, _) = SslManager::generate_self_signed("api.v2.example.org").expect("subdomain");
    assert!(cert.contains("BEGIN CERTIFICATE"));
}
