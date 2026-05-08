//! Challenge credit token encoding and decoding.
//!
//! Token format: `base64url(payload).base64url(hmac_sha256(secret, payload))`
//!
//! Payload JSON: `{"a":"<owner_id>","i":<issued_ms>,"n":"<nonce_hex>","t":<ttl_secs>}`

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// Token payload containing actor binding and timing information.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TokenPayload {
    /// Actor owner ID (bound identity).
    #[serde(rename = "a")]
    pub actor_id: String,
    /// Issued timestamp in milliseconds.
    #[serde(rename = "i")]
    pub issued_ms: i64,
    /// Unique nonce (hex-encoded 128-bit).
    #[serde(rename = "n")]
    pub nonce: String,
    /// TTL in seconds.
    #[serde(rename = "t")]
    pub ttl_secs: u32,
}

/// Reason for token verification failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    /// Token format is invalid (not two parts, bad base64).
    MalformedToken,
    /// HMAC signature does not match.
    BadSignature,
    /// Token has expired.
    Expired,
    /// Actor ID in token does not match request actor.
    BindingMismatch,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedToken => write!(f, "malformed token"),
            Self::BadSignature => write!(f, "bad signature"),
            Self::Expired => write!(f, "expired"),
            Self::BindingMismatch => write!(f, "binding mismatch"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Encode a token payload into a signed token string.
///
/// # Panics
/// Never panics in practice — `TokenPayload` contains only primitive types
/// (String, i64, u32) that always serialize, and HMAC-SHA256 accepts any key length.
#[must_use]
pub fn encode(payload: &TokenPayload, secret: &[u8; 32]) -> String {
    // TokenPayload only contains String/i64/u32 — serialization cannot fail
    let Ok(payload_json) = serde_json::to_string(payload) else {
        // Fallback for impossible case: return empty token that will fail verification
        tracing::error!("BUG: TokenPayload serialization failed");
        return String::new();
    };
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    // HMAC-SHA256 accepts any key length; 32-byte keys always succeed
    let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
        tracing::error!("BUG: HMAC-SHA256 rejected 32-byte key");
        return String::new();
    };
    mac.update(payload_json.as_bytes());
    let sig = mac.finalize().into_bytes();
    let sig_b64 = URL_SAFE_NO_PAD.encode(sig);

    format!("{payload_b64}.{sig_b64}")
}

/// Decode and verify a token, returning the payload if valid.
///
/// # Arguments
/// * `token` - The token string to verify
/// * `secret` - HMAC secret key
/// * `now_ms` - Current timestamp in milliseconds
///
/// # Errors
/// Returns `VerifyError` if token is malformed, expired, or signature invalid.
pub fn decode_and_verify(token: &str, secret: &[u8; 32], now_ms: i64) -> Result<TokenPayload, VerifyError> {
    // Split into payload and signature parts
    let (payload_b64, sig_b64) = token.split_once('.').ok_or(VerifyError::MalformedToken)?;

    // Decode payload
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| VerifyError::MalformedToken)?;

    // Decode signature
    let provided_sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| VerifyError::MalformedToken)?;

    // Compute expected signature
    let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| VerifyError::MalformedToken)?;
    mac.update(&payload_bytes);
    let expected_sig = mac.finalize().into_bytes();

    // Constant-time comparison to prevent timing attacks
    if provided_sig.len() != expected_sig.len() {
        return Err(VerifyError::BadSignature);
    }
    if provided_sig.ct_eq(&expected_sig[..]).unwrap_u8() != 1 {
        return Err(VerifyError::BadSignature);
    }

    // Parse payload JSON
    let payload: TokenPayload = serde_json::from_slice(&payload_bytes).map_err(|_| VerifyError::MalformedToken)?;

    // Check expiration
    let expiry_ms = payload.issued_ms.saturating_add(i64::from(payload.ttl_secs) * 1000);
    if now_ms > expiry_ms {
        return Err(VerifyError::Expired);
    }

    Ok(payload)
}

/// Generate a random 128-bit nonce as hex string.
#[must_use]
pub fn generate_nonce() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn encode_decode_roundtrip() {
        let secret = test_secret();
        let payload = TokenPayload {
            actor_id: "test-actor".into(),
            issued_ms: 1_700_000_000_000,
            nonce: generate_nonce(),
            ttl_secs: 300,
        };

        let token = encode(&payload, &secret);
        let decoded = decode_and_verify(&token, &secret, 1_700_000_000_000).unwrap();

        assert_eq!(decoded.actor_id, payload.actor_id);
        assert_eq!(decoded.issued_ms, payload.issued_ms);
        assert_eq!(decoded.ttl_secs, payload.ttl_secs);
    }

    #[test]
    fn decode_rejects_tampered_payload() {
        let secret = test_secret();
        let payload = TokenPayload {
            actor_id: "test-actor".into(),
            issued_ms: 1_700_000_000_000,
            nonce: generate_nonce(),
            ttl_secs: 300,
        };

        let token = encode(&payload, &secret);
        // Tamper with the payload by flipping a byte
        let mut bytes: Vec<u8> = token.into_bytes();
        if bytes.len() > 5 {
            bytes[5] = bytes[5].wrapping_add(1);
        }
        let tampered = String::from_utf8_lossy(&bytes).to_string();

        let result = decode_and_verify(&tampered, &secret, 1_700_000_000_000);
        assert!(matches!(
            result,
            Err(VerifyError::BadSignature | VerifyError::MalformedToken)
        ));
    }

    #[test]
    fn decode_rejects_wrong_secret() {
        let secret = test_secret();
        let payload = TokenPayload {
            actor_id: "test-actor".into(),
            issued_ms: 1_700_000_000_000,
            nonce: generate_nonce(),
            ttl_secs: 300,
        };

        let token = encode(&payload, &secret);
        let wrong_secret = [99u8; 32];

        let result = decode_and_verify(&token, &wrong_secret, 1_700_000_000_000);
        assert!(matches!(result, Err(VerifyError::BadSignature)));
    }

    #[test]
    fn decode_rejects_expired() {
        let secret = test_secret();
        let payload = TokenPayload {
            actor_id: "test-actor".into(),
            issued_ms: 1_700_000_000_000,
            nonce: generate_nonce(),
            ttl_secs: 300, // 5 minutes
        };

        let token = encode(&payload, &secret);
        // Check at 6 minutes later
        let result = decode_and_verify(&token, &secret, 1_700_000_360_000);
        assert!(matches!(result, Err(VerifyError::Expired)));
    }

    #[test]
    fn decode_rejects_malformed() {
        let secret = test_secret();

        // No dot separator
        assert!(matches!(
            decode_and_verify("nodot", &secret, 0),
            Err(VerifyError::MalformedToken)
        ));

        // Bad base64
        assert!(matches!(
            decode_and_verify("!!!.???", &secret, 0),
            Err(VerifyError::MalformedToken)
        ));

        // Valid base64 but not JSON
        let not_json = URL_SAFE_NO_PAD.encode(b"not json");
        let fake_sig = URL_SAFE_NO_PAD.encode(&[0u8; 32]);
        assert!(matches!(
            decode_and_verify(&format!("{not_json}.{fake_sig}"), &secret, 0),
            Err(VerifyError::BadSignature | VerifyError::MalformedToken)
        ));
    }

    #[test]
    fn generate_nonce_is_32_hex_chars() {
        let nonce = generate_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
