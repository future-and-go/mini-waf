//! FR-006/FR-025 Phase 8: Challenge Credit Token System.
//!
//! Issues HMAC-signed credit tokens on successful challenge completion (e.g., JS-PoW).
//! Tokens are single-use and bound to the actor identity to prevent replay and sharing.
//!
//! Token verification outcomes map to risk score deltas:
//! - Valid: -25 (credit for passing challenge)
//! - Invalid: +20 (penalty for bad token)
//! - Replay: +30 (penalty for replay attempt)
//! - Expired: +10 (mild penalty for expected drift)

pub mod nonce_store;
pub mod secret;
pub mod token;

use std::path::Path;
use std::sync::Arc;

use anyhow::Result;

use crate::risk::config::ChallengeConfig;

pub use nonce_store::{ConsumeResult, NonceStore};
pub use secret::HmacSecret;
pub use token::{TokenPayload, VerifyError};

/// Outcome of token verification for risk scoring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Token valid — apply credit delta.
    Valid {
        /// The nonce that was consumed (for logging).
        nonce: String,
    },
    /// Token invalid (malformed, bad signature, binding mismatch).
    Invalid(InvalidReason),
    /// Token replay detected — nonce already consumed.
    Replay,
    /// Token expired.
    Expired,
}

/// Reason for invalid token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidReason {
    /// Token format is malformed.
    MalformedToken,
    /// HMAC signature verification failed.
    BadSignature,
    /// Actor ID in token doesn't match request actor.
    BindingMismatch,
}

impl std::fmt::Display for InvalidReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedToken => write!(f, "malformed_token"),
            Self::BadSignature => write!(f, "bad_signature"),
            Self::BindingMismatch => write!(f, "binding_mismatch"),
        }
    }
}

/// Issues challenge credit tokens.
///
/// Called by the challenge page (FR-006) on successful `PoW` completion.
pub struct ChallengeIssuer {
    secret: Arc<HmacSecret>,
    ttl_secs: u32,
}

impl ChallengeIssuer {
    /// Create a new issuer with the given secret and TTL.
    #[must_use]
    pub const fn new(secret: Arc<HmacSecret>, ttl_secs: u32) -> Self {
        Self { secret, ttl_secs }
    }

    /// Issue a token for the given actor owner ID.
    ///
    /// The token binds to this `owner_id` — verification will fail if presented
    /// by a different actor.
    #[must_use]
    pub fn issue(&self, owner_id: &str, now_ms: i64) -> String {
        let payload = TokenPayload {
            actor_id: owner_id.to_string(),
            issued_ms: now_ms,
            nonce: token::generate_nonce(),
            ttl_secs: self.ttl_secs,
        };
        token::encode(&payload, self.secret.as_bytes())
    }

    /// Get the TTL in seconds.
    #[must_use]
    pub const fn ttl_secs(&self) -> u32 {
        self.ttl_secs
    }
}

/// Verifies challenge credit tokens.
///
/// Called inline by the Scorer on every request that bears the credit header.
pub struct ChallengeVerifier {
    secret: Arc<HmacSecret>,
    nonce_store: Arc<NonceStore>,
}

impl ChallengeVerifier {
    /// Create a new verifier with the given secret and nonce store.
    #[must_use]
    pub const fn new(secret: Arc<HmacSecret>, nonce_store: Arc<NonceStore>) -> Self {
        Self { secret, nonce_store }
    }

    /// Verify a token and consume its nonce if valid.
    ///
    /// # Arguments
    /// * `token` - The token string from the credit header
    /// * `request_owner_id` - The owner ID of the requesting actor (for binding check)
    /// * `now_ms` - Current timestamp in milliseconds
    ///
    /// # Returns
    /// `VerifyOutcome` indicating the result for risk scoring.
    pub async fn verify(&self, token: &str, request_owner_id: &str, now_ms: i64) -> VerifyOutcome {
        // Step 1-3: Decode, verify HMAC, check expiration
        let payload = match token::decode_and_verify(token, self.secret.as_bytes(), now_ms) {
            Ok(p) => p,
            Err(VerifyError::MalformedToken) => return VerifyOutcome::Invalid(InvalidReason::MalformedToken),
            Err(VerifyError::BadSignature) => return VerifyOutcome::Invalid(InvalidReason::BadSignature),
            Err(VerifyError::Expired) => return VerifyOutcome::Expired,
            Err(VerifyError::BindingMismatch) => return VerifyOutcome::Invalid(InvalidReason::BindingMismatch),
        };

        // Step 4: Check actor binding
        if payload.actor_id != request_owner_id {
            tracing::debug!(
                token_actor = %payload.actor_id,
                request_actor = %request_owner_id,
                "challenge credit: binding mismatch"
            );
            return VerifyOutcome::Invalid(InvalidReason::BindingMismatch);
        }

        // Step 5: Try to consume nonce
        match self.nonce_store.try_consume(&payload.nonce).await {
            ConsumeResult::Consumed | ConsumeResult::ConsumedWithWarning => {
                VerifyOutcome::Valid { nonce: payload.nonce }
            }
            ConsumeResult::Replay => {
                tracing::warn!(
                    nonce = %payload.nonce,
                    actor = %payload.actor_id,
                    "challenge credit: replay detected"
                );
                VerifyOutcome::Replay
            }
        }
    }

    /// Check if a nonce has been consumed (for testing/debugging).
    #[must_use]
    pub fn is_nonce_consumed(&self, nonce: &str) -> bool {
        self.nonce_store.is_consumed(nonce)
    }
}

/// Builder for creating challenge credit components from config.
pub struct ChallengeBuilder;

impl ChallengeBuilder {
    /// Create issuer and verifier from config.
    ///
    /// # Errors
    /// Returns error if HMAC secret cannot be loaded/generated.
    pub fn from_config(cfg: &ChallengeConfig) -> Result<(ChallengeIssuer, ChallengeVerifier)> {
        let secret_path = cfg
            .hmac_secret_path
            .as_deref()
            .unwrap_or("/var/lib/waf/challenge-hmac.key");

        let secret = Arc::new(HmacSecret::load_or_init(Path::new(secret_path))?);
        let nonce_store = Arc::new(NonceStore::new(cfg.lru_size, cfg.ttl_secs));

        let issuer = ChallengeIssuer::new(Arc::clone(&secret), cfg.ttl_secs);
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        Ok((issuer, verifier))
    }

    /// Create issuer and verifier with Redis backend for cluster-wide nonce tracking.
    #[cfg(feature = "redis-store")]
    pub fn from_config_with_redis(
        cfg: &ChallengeConfig,
        redis_conn: redis::aio::ConnectionManager,
        redis_timeout: std::time::Duration,
    ) -> Result<(ChallengeIssuer, ChallengeVerifier)> {
        let secret_path = cfg
            .hmac_secret_path
            .as_deref()
            .unwrap_or("/var/lib/waf/challenge-hmac.key");

        let secret = Arc::new(HmacSecret::load_or_init(Path::new(secret_path))?);
        let redis_backend = nonce_store::NonceRedisBackend::new(redis_conn, redis_timeout);
        let nonce_store = Arc::new(NonceStore::with_redis(cfg.lru_size, cfg.ttl_secs, redis_backend));

        let issuer = ChallengeIssuer::new(Arc::clone(&secret), cfg.ttl_secs);
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        Ok((issuer, verifier))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> Arc<HmacSecret> {
        // Fixed 32-byte key for deterministic tests (no file I/O, no race conditions)
        Arc::new(HmacSecret::from_bytes([42u8; 32]))
    }

    #[tokio::test]
    async fn issue_and_verify_valid_token() {
        let secret = test_secret();
        let nonce_store = Arc::new(NonceStore::new(100, 300));

        let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        let now = 1_700_000_000_000_i64;
        let owner_id = "actor-123";

        let token = issuer.issue(owner_id, now);
        let result = verifier.verify(&token, owner_id, now).await;

        assert!(matches!(result, VerifyOutcome::Valid { .. }));
    }

    #[tokio::test]
    async fn verify_detects_replay() {
        let secret = test_secret();
        let nonce_store = Arc::new(NonceStore::new(100, 300));

        let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        let now = 1_700_000_000_000_i64;
        let owner_id = "actor-123";
        let token = issuer.issue(owner_id, now);

        // First verification should succeed
        let first = verifier.verify(&token, owner_id, now).await;
        assert!(matches!(first, VerifyOutcome::Valid { .. }));

        // Second verification should detect replay
        let second = verifier.verify(&token, owner_id, now).await;
        assert!(matches!(second, VerifyOutcome::Replay));
    }

    #[tokio::test]
    async fn verify_detects_binding_mismatch() {
        let secret = test_secret();
        let nonce_store = Arc::new(NonceStore::new(100, 300));

        let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300);
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        let now = 1_700_000_000_000_i64;
        let token = issuer.issue("actor-alice", now);

        // Verify with different actor
        let result = verifier.verify(&token, "actor-bob", now).await;
        assert!(matches!(result, VerifyOutcome::Invalid(InvalidReason::BindingMismatch)));
    }

    #[tokio::test]
    async fn verify_detects_expired() {
        let secret = test_secret();
        let nonce_store = Arc::new(NonceStore::new(100, 300));

        let issuer = ChallengeIssuer::new(Arc::clone(&secret), 300); // 5 min TTL
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        let issued_at = 1_700_000_000_000_i64;
        let token = issuer.issue("actor-123", issued_at);

        // Verify 6 minutes later
        let later = issued_at + 360_000;
        let result = verifier.verify(&token, "actor-123", later).await;
        assert!(matches!(result, VerifyOutcome::Expired));
    }

    #[tokio::test]
    async fn verify_detects_bad_signature() {
        let secret = test_secret();
        let nonce_store = Arc::new(NonceStore::new(100, 300));
        let verifier = ChallengeVerifier::new(secret, nonce_store);

        // Tampered token
        let result = verifier.verify("tampered.signature", "actor-123", 0).await;
        assert!(matches!(
            result,
            VerifyOutcome::Invalid(InvalidReason::MalformedToken | InvalidReason::BadSignature)
        ));
    }
}
