//! FR-006/FR-025 — Challenge credit verification matrix.
//!
//! Covers Valid / Invalid / Replay / Expired outcomes plus secret persistence.

use std::sync::Arc;

use tempfile::tempdir;
use waf_engine::risk::challenge_credit::{
    ChallengeIssuer, ChallengeVerifier, HmacSecret, InvalidReason, NonceStore, VerifyOutcome,
};

fn fixed_secret() -> Arc<HmacSecret> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");
    std::fs::write(&path, [7u8; 32]).unwrap();
    let s = HmacSecret::load_or_init(&path).unwrap();
    // Keep tempdir alive via leak — tests only run briefly.
    Box::leak(Box::new(dir));
    Arc::new(s)
}

fn alt_secret() -> Arc<HmacSecret> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");
    std::fs::write(&path, [9u8; 32]).unwrap();
    let s = HmacSecret::load_or_init(&path).unwrap();
    Box::leak(Box::new(dir));
    Arc::new(s)
}

#[tokio::test]
async fn valid_token_yields_valid_outcome() {
    let secret = fixed_secret();
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let now = 1_700_000_000_000_i64;
    let owner = "actor-alpha";
    let token = issuer.issue(owner, now);
    assert_eq!(issuer.ttl_secs(), 300);

    let outcome = verifier.verify(&token, owner, now).await;
    assert!(matches!(outcome, VerifyOutcome::Valid { .. }));
}

#[tokio::test]
async fn replay_detected_on_second_use() {
    let secret = fixed_secret();
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let token = issuer.issue("actor", 1000);
    let first = verifier.verify(&token, "actor", 1000).await;
    assert!(matches!(first, VerifyOutcome::Valid { .. }));
    let second = verifier.verify(&token, "actor", 1100).await;
    assert!(matches!(second, VerifyOutcome::Replay));
}

#[tokio::test]
async fn binding_mismatch_returns_invalid() {
    let secret = fixed_secret();
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let token = issuer.issue("alice", 1000);
    let outcome = verifier.verify(&token, "bob", 1000).await;
    assert!(matches!(
        outcome,
        VerifyOutcome::Invalid(InvalidReason::BindingMismatch)
    ));
}

#[tokio::test]
async fn expired_token_returns_expired() {
    let secret = fixed_secret();
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 1); // 1 second TTL
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let issued_at = 1_700_000_000_000_i64;
    let token = issuer.issue("actor", issued_at);
    // Verify 5 seconds later — way past TTL.
    let outcome = verifier.verify(&token, "actor", issued_at + 5_000).await;
    assert!(matches!(outcome, VerifyOutcome::Expired));
}

#[tokio::test]
async fn malformed_token_returns_invalid() {
    let secret = fixed_secret();
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let outcome = verifier.verify("not-a-valid-token", "actor", 1000).await;
    assert!(matches!(
        outcome,
        VerifyOutcome::Invalid(InvalidReason::MalformedToken | InvalidReason::BadSignature)
    ));
}

#[tokio::test]
async fn bad_signature_returns_invalid_signature() {
    let secret_a = fixed_secret();
    let secret_b = alt_secret();
    let issuer = ChallengeIssuer::new(secret_a, 300);
    let verifier_alt = ChallengeVerifier::new(secret_b, Arc::new(NonceStore::new(64, 300)));

    let token = issuer.issue("actor", 1000);
    let outcome = verifier_alt.verify(&token, "actor", 1000).await;
    assert!(matches!(outcome, VerifyOutcome::Invalid(InvalidReason::BadSignature)));
}

#[test]
fn secret_persistence_round_trip() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");

    // First call generates and persists.
    let s1 = HmacSecret::load_or_init(&path).expect("init");
    let bytes_first = *s1.as_bytes();

    // Second call must read the same secret back.
    let s2 = HmacSecret::load_or_init(&path).expect("reload");
    assert_eq!(s2.as_bytes(), &bytes_first);
}

#[cfg(unix)]
#[test]
fn secret_file_mode_is_0600() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");
    let _ = HmacSecret::load_or_init(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "HMAC secret must be 0600 on Unix");
}

#[test]
fn secret_load_rejects_short_file() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("short.key");
    std::fs::write(&path, [1u8; 5]).unwrap();
    let err = HmacSecret::load_or_init(&path).unwrap_err();
    assert!(err.to_string().contains("32 bytes"));
}

#[test]
fn secret_debug_redacts() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");
    std::fs::write(&path, [1u8; 32]).unwrap();
    let s = HmacSecret::load_or_init(&path).unwrap();
    let dbg = format!("{s:?}");
    assert!(dbg.contains("REDACTED"), "got {dbg}");
}

#[tokio::test]
async fn nonce_consumed_introspection_works() {
    let secret = fixed_secret();
    let nonce_store = Arc::new(NonceStore::new(64, 300));
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let token = issuer.issue("actor", 2000);
    let outcome = verifier.verify(&token, "actor", 2000).await;
    let nonce = match outcome {
        VerifyOutcome::Valid { nonce } => nonce,
        other => panic!("expected Valid, got {other:?}"),
    };
    assert!(verifier.is_nonce_consumed(&nonce));
}
