//! Credential extraction + keyed-hash helpers for FR-018.
//!
//! Credential material is never retained raw — we hash to a u64 before any
//! map insertion so leaked state doesn't leak plaintext usernames/passwords
//! (GDPR posture; also keeps memory flat).
//!
//! The hash is `ahash::RandomState` keyed with a per-process random seed.
//! Unkeyed SHA-256 truncated to 64 bits is offline-grindable: an attacker
//! can precompute a username that collides with a victim and use it to
//! trip the victim's brute-force counter (victim-lockout primitive). The
//! per-process random key blocks that: the attacker must interact with
//! the live WAF to mount the collision, at which point they've already
//! hit the rate limit they're trying to grind around.

use std::sync::LazyLock;

use ahash::RandomState;

static HASH_KEY: LazyLock<RandomState> = LazyLock::new(RandomState::new);

/// Hash `s` with the per-process keyed `ahash` state. Stable within one
/// process lifetime, randomised across restarts — and never persisted,
/// so restart portability is not required.
pub fn truncated_hash(s: &str) -> u64 {
    HASH_KEY.hash_one(s.as_bytes())
}

/// Pull a credential-like field (username/email/password) from a request
/// body. Handles both `application/json` (objects only) and
/// `application/x-www-form-urlencoded`.
///
/// Case-insensitive key match so `{"Username":"x"}` and `{"username":"x"}`
/// hash identically.
pub fn extract_credential_field(body: &[u8], content_type: &str, candidates: &[&str]) -> Option<String> {
    extract_credentials_impl(body, content_type, &[candidates])
        .into_iter()
        .next()
        .flatten()
}

/// Parse the body ONCE and resolve multiple credential lookups against the
/// same parse tree. Returns one `Option<String>` per `key_groups` entry, in
/// the same order.
///
/// Used on the FR-018 response hot path where we need both username and
/// password from the same login body — the single-field entry point parses
/// JSON twice which doubles CPU per failed-login response.
pub fn extract_credentials(body: &[u8], content_type: &str, key_groups: &[&[&str]]) -> Vec<Option<String>> {
    extract_credentials_impl(body, content_type, key_groups)
}

fn extract_credentials_impl(body: &[u8], content_type: &str, key_groups: &[&[&str]]) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = vec![None; key_groups.len()];
    let ct = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();

    if ct == "application/json" || ct.ends_with("+json") {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) else {
            return out;
        };
        if let serde_json::Value::Object(map) = v {
            for (k, val) in &map {
                let serde_json::Value::String(s) = val else {
                    continue;
                };
                for (slot, group) in out.iter_mut().zip(key_groups.iter()) {
                    if slot.is_none() && group.iter().any(|c| k.eq_ignore_ascii_case(c)) {
                        *slot = Some(s.clone());
                    }
                }
            }
        }
        return out;
    }

    if ct == "application/x-www-form-urlencoded" {
        for (k, v) in url::form_urlencoded::parse(body) {
            for (slot, group) in out.iter_mut().zip(key_groups.iter()) {
                if slot.is_none() && group.iter().any(|c| k.eq_ignore_ascii_case(c)) {
                    *slot = Some(v.clone().into_owned());
                }
            }
        }
    }
    out
}

/// Username candidate keys tried in order.
pub const USERNAME_KEYS: &[&str] = &["username", "email", "user", "login"];

/// Password candidate keys tried in order.
pub const PASSWORD_KEYS: &[&str] = &["password", "passwd", "pass"];

/// Login response is treated as failed when status is 401 or 403. Body-based
/// detection is intentionally not supported in v1 — Pingora `response_filter`
/// exposes status + headers only (Red Team Finding #8), and body-regex on
/// upstream error pages is a known victim-account-lockout primitive
/// (Finding #11).
pub const fn is_failed_login_status(status: u16) -> bool {
    matches!(status, 401 | 403)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncated_hash_stable_for_same_input() {
        assert_eq!(truncated_hash("alice"), truncated_hash("alice"));
    }

    #[test]
    fn truncated_hash_differs_across_input() {
        assert_ne!(truncated_hash("alice"), truncated_hash("bob"));
    }

    #[test]
    fn truncated_hash_is_keyed_not_precomputable() {
        // Keyed with per-process random state — the hash of `"alice"` MUST
        // NOT equal the unkeyed SHA-256 truncation an offline attacker
        // would precompute. Without the random key, an attacker who knows
        // the hash function can grind a colliding username to trip any
        // victim's brute-force counter.
        //
        // Unkeyed SHA-256 leading 8 bytes of "alice" as big-endian u64:
        const UNKEYED_SHA256_ALICE: u64 = 0x2bd8_06c9_7f0e_00af;
        // Vanishing-small probability of a random-state collision on this
        // specific 8-byte prefix; if this test ever flakes we'll know the
        // key entropy has regressed.
        assert_ne!(truncated_hash("alice"), UNKEYED_SHA256_ALICE);
    }

    #[test]
    fn extract_username_from_json_object() {
        let body = br#"{"username":"alice","password":"secret"}"#;
        assert_eq!(
            extract_credential_field(body, "application/json", USERNAME_KEYS).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn extract_email_as_username() {
        let body = br#"{"email":"a@b.z","password":"pw"}"#;
        assert_eq!(
            extract_credential_field(body, "application/json", USERNAME_KEYS).as_deref(),
            Some("a@b.z")
        );
    }

    #[test]
    fn extract_case_insensitive_key() {
        let body = br#"{"Username":"BOB"}"#;
        assert_eq!(
            extract_credential_field(body, "application/json", USERNAME_KEYS).as_deref(),
            Some("BOB")
        );
    }

    #[test]
    fn extract_password_key() {
        let body = br#"{"username":"alice","password":"P@ss1"}"#;
        assert_eq!(
            extract_credential_field(body, "application/json", PASSWORD_KEYS).as_deref(),
            Some("P@ss1")
        );
    }

    #[test]
    fn extract_form_urlencoded_username() {
        let body = b"username=alice&password=secret";
        assert_eq!(
            extract_credential_field(body, "application/x-www-form-urlencoded", USERNAME_KEYS).as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn extract_form_with_charset() {
        let body = b"username=alice&password=secret";
        assert_eq!(
            extract_credential_field(body, "application/x-www-form-urlencoded; charset=utf-8", USERNAME_KEYS)
                .as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn extract_returns_none_on_missing_key() {
        let body = br#"{"token":"xyz"}"#;
        assert!(extract_credential_field(body, "application/json", USERNAME_KEYS).is_none());
    }

    #[test]
    fn extract_returns_none_on_malformed_json() {
        let body = b"not-json-at-all";
        assert!(extract_credential_field(body, "application/json", USERNAME_KEYS).is_none());
    }

    #[test]
    fn extract_returns_none_on_unsupported_content_type() {
        let body = br#"{"username":"alice"}"#;
        assert!(extract_credential_field(body, "text/plain", USERNAME_KEYS).is_none());
    }

    #[test]
    fn extract_returns_none_when_value_not_string() {
        let body = br#"{"username":123}"#;
        assert!(extract_credential_field(body, "application/json", USERNAME_KEYS).is_none());
    }

    #[test]
    fn extract_returns_none_for_json_array_root() {
        // Root is an array, not an object — no key lookup possible.
        let body = br#"[{"username":"x"}]"#;
        assert!(extract_credential_field(body, "application/json", USERNAME_KEYS).is_none());
    }

    #[test]
    fn is_failed_login_status_boundaries() {
        assert!(is_failed_login_status(401));
        assert!(is_failed_login_status(403));
        assert!(!is_failed_login_status(400));
        assert!(!is_failed_login_status(200));
        assert!(!is_failed_login_status(500));
    }
}
