//! FR-006 — Challenge flow integration tests.
//!
//! Tests the full challenge lifecycle: issue → verify flow, concurrent challenges,
//! replay protection, and binding verification.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::missing_docs_in_private_items,
    clippy::significant_drop_tightening
)]

use std::sync::Arc;

use tempfile::tempdir;
use tokio::task::JoinSet;
use waf_engine::risk::challenge_credit::{
    ChallengeIssuer, ChallengeVerifier, HmacSecret, InvalidReason, NonceStore, VerifyOutcome,
};

fn test_secret() -> Arc<HmacSecret> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");
    std::fs::write(&path, [42u8; 32]).unwrap();
    let s = HmacSecret::load_or_init(&path).unwrap();
    Box::leak(Box::new(dir));
    Arc::new(s)
}

fn file_based_secret() -> Arc<HmacSecret> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac.key");
    std::fs::write(&path, [77u8; 32]).unwrap();
    let s = HmacSecret::load_or_init(&path).unwrap();
    Box::leak(Box::new(dir));
    Arc::new(s)
}

#[tokio::test]
async fn challenge_issue_verify_full_flow() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(1000, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);

    let owner_id = "192.168.1.1|ja3hash|ja4hash";
    let now_ms = chrono::Utc::now().timestamp_millis();

    let token = issuer.issue(owner_id, now_ms);
    assert!(!token.is_empty(), "issued token should not be empty");

    let result = verifier.verify(&token, owner_id, now_ms).await;
    assert!(matches!(result, VerifyOutcome::Valid { .. }), "valid token should verify");
}

#[tokio::test]
async fn challenge_binding_mismatch_rejected() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(1000, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);

    let binding_issuer = "192.168.1.1|hash1";
    let binding_requester = "192.168.1.2|hash2";
    let now_ms = chrono::Utc::now().timestamp_millis();

    let token = issuer.issue(binding_issuer, now_ms);

    let result = verifier.verify(&token, binding_requester, now_ms).await;
    assert!(
        matches!(result, VerifyOutcome::Invalid(InvalidReason::BindingMismatch)),
        "different binding should fail"
    );
}

#[tokio::test]
async fn challenge_replay_rejected_immediately() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(1000, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), Arc::clone(&nonce_store));

    let binding = "test_binding_replay";
    let now_ms = chrono::Utc::now().timestamp_millis();

    let token = issuer.issue(binding, now_ms);

    let first = verifier.verify(&token, binding, now_ms).await;
    assert!(matches!(first, VerifyOutcome::Valid { .. }), "first use should succeed");

    let second = verifier.verify(&token, binding, now_ms).await;
    assert!(matches!(second, VerifyOutcome::Replay), "replay should be detected");

    let third = verifier.verify(&token, binding, now_ms + 1000).await;
    assert!(matches!(third, VerifyOutcome::Replay), "replay persists across time");
}

#[tokio::test]
async fn challenge_expired_after_ttl() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(1000, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 1);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);

    let binding = "expiry_test";
    let now_ms = chrono::Utc::now().timestamp_millis();

    let token = issuer.issue(binding, now_ms);

    let future_ms = now_ms + 2000;
    let result = verifier.verify(&token, binding, future_ms).await;
    assert!(matches!(result, VerifyOutcome::Expired), "token should expire after TTL");
}

#[tokio::test]
async fn challenge_valid_just_before_expiry() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(1000, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 10);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);

    let binding = "near_expiry_test";
    let now_ms = 1_700_000_000_000_i64;

    let token = issuer.issue(binding, now_ms);

    let just_before = now_ms + 9_900;
    let result = verifier.verify(&token, binding, just_before).await;
    assert!(matches!(result, VerifyOutcome::Valid { .. }), "should be valid just before expiry");
}

#[tokio::test]
async fn concurrent_challenges_no_race_conditions() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(10000, 300));

    let issuer = Arc::new(ChallengeIssuer::new(Arc::clone(&secret), 300));
    let verifier = Arc::new(ChallengeVerifier::new(Arc::clone(&secret), nonce_store));

    let mut set = JoinSet::new();
    let num_challenges = 1000;

    for i in 0..num_challenges {
        let issuer = Arc::clone(&issuer);
        let verifier = Arc::clone(&verifier);

        set.spawn(async move {
            let binding = format!("concurrent_actor_{i}");
            let now_ms = chrono::Utc::now().timestamp_millis();

            let token = issuer.issue(&binding, now_ms);
            let result = verifier.verify(&token, &binding, now_ms).await;

            match result {
                VerifyOutcome::Valid { .. } => Ok(i),
                other => Err(format!("challenge {i} failed: {other:?}")),
            }
        });
    }

    let mut success_count = 0;
    let mut failures = Vec::new();

    while let Some(result) = set.join_next().await {
        match result {
            Ok(Ok(_)) => success_count += 1,
            Ok(Err(msg)) => failures.push(msg),
            Err(e) => failures.push(format!("task panic: {e}")),
        }
    }

    assert!(
        failures.is_empty(),
        "concurrent challenges failed: {:?}",
        failures
    );
    assert_eq!(success_count, num_challenges, "all challenges should succeed");
}

#[tokio::test]
async fn concurrent_same_actor_only_first_succeeds() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(1000, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = Arc::new(ChallengeVerifier::new(Arc::clone(&secret), nonce_store));

    let binding = "shared_actor";
    let now_ms = chrono::Utc::now().timestamp_millis();
    let token = issuer.issue(binding, now_ms);

    let mut set = JoinSet::new();
    for _ in 0..10 {
        let verifier = Arc::clone(&verifier);
        let token = token.clone();
        let binding = binding.to_string();

        set.spawn(async move { verifier.verify(&token, &binding, now_ms).await });
    }

    let mut valid_count = 0;
    let mut replay_count = 0;

    while let Some(result) = set.join_next().await {
        match result.unwrap() {
            VerifyOutcome::Valid { .. } => valid_count += 1,
            VerifyOutcome::Replay => replay_count += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }

    assert_eq!(valid_count, 1, "exactly one should succeed");
    assert_eq!(replay_count, 9, "rest should be replays");
}

fn alt_secret() -> Arc<HmacSecret> {
    let dir = tempdir().unwrap();
    let path = dir.path().join("hmac_alt.key");
    std::fs::write(&path, [99u8; 32]).unwrap();
    let s = HmacSecret::load_or_init(&path).unwrap();
    Box::leak(Box::new(dir));
    Arc::new(s)
}

#[tokio::test]
async fn different_secrets_produce_bad_signature() {
    let secret_a = test_secret();
    let secret_b = alt_secret();

    let issuer = ChallengeIssuer::new(secret_a, 300);
    let verifier = ChallengeVerifier::new(secret_b, Arc::new(NonceStore::new(100, 300)));

    let token = issuer.issue("actor", 1000);
    let result = verifier.verify(&token, "actor", 1000).await;

    assert!(matches!(result, VerifyOutcome::Invalid(InvalidReason::BadSignature)));
}

#[tokio::test]
async fn malformed_token_rejected() {
    let secret = test_secret();
    let verifier = ChallengeVerifier::new(secret, Arc::new(NonceStore::new(100, 300)));

    let long_token = "x".repeat(10000);
    let malformed_tokens = [
        "",
        "not-a-token",
        "a.b",
        "truncated.sig.nature",
        long_token.as_str(),
    ];

    for token in malformed_tokens {
        let result = verifier.verify(token, "actor", 1000).await;
        assert!(
            matches!(result, VerifyOutcome::Invalid(_)),
            "malformed token '{token}' should be invalid"
        );
    }
}

#[tokio::test]
async fn nonce_store_capacity_enforced() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(10, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), Arc::clone(&nonce_store));

    let now_ms = 1_700_000_000_000_i64;

    for i in 0..20 {
        let binding = format!("actor_{i}");
        let token = issuer.issue(&binding, now_ms);
        let result = verifier.verify(&token, &binding, now_ms).await;
        assert!(matches!(result, VerifyOutcome::Valid { .. }), "token {i} should verify");
    }
}

#[tokio::test]
async fn token_ttl_propagates_from_issuer() {
    let secret = test_secret();
    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 600);

    assert_eq!(issuer.ttl_secs(), 600, "TTL should be accessible");

    let nonce_store = Arc::new(NonceStore::new(100, 600));
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);

    let now_ms = 1_700_000_000_000_i64;
    let token = issuer.issue("actor", now_ms);

    let within_ttl = now_ms + 500_000;
    let result = verifier.verify(&token, "actor", within_ttl).await;
    assert!(matches!(result, VerifyOutcome::Valid { .. }));
}

#[tokio::test]
async fn file_based_secret_works() {
    let secret = file_based_secret();
    let nonce_store = Arc::new(NonceStore::new(100, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(secret, nonce_store);

    let token = issuer.issue("file_secret_actor", 1000);
    let result = verifier.verify(&token, "file_secret_actor", 1000).await;

    assert!(matches!(result, VerifyOutcome::Valid { .. }));
}

#[tokio::test]
async fn consumed_nonce_is_introspectable() {
    let secret = test_secret();
    let nonce_store = Arc::new(NonceStore::new(100, 300));

    let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
    let verifier = ChallengeVerifier::new(Arc::clone(&secret), nonce_store);

    let token = issuer.issue("introspect_actor", 2000);
    let outcome = verifier.verify(&token, "introspect_actor", 2000).await;

    let nonce = match outcome {
        VerifyOutcome::Valid { nonce } => nonce,
        other => panic!("expected Valid, got {other:?}"),
    };

    assert!(verifier.is_nonce_consumed(&nonce), "nonce should be marked consumed");
    assert!(!verifier.is_nonce_consumed("nonexistent"), "unknown nonce should not be consumed");
}
