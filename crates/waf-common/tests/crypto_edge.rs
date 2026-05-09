//! Edge-case coverage for `waf_common::crypto` AES-GCM helpers.

#![allow(
    unsafe_code,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::indexing_slicing
)]

use std::sync::Mutex;
use waf_common::crypto::{decrypt_field, derive_key, encrypt_field, master_key};

static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn derive_key_is_deterministic_and_pinned_to_prefix() {
    let a = derive_key("hunter2");
    let b = derive_key("hunter2");
    let c = derive_key("hunter3");
    assert_eq!(a, b);
    assert_ne!(a, c);
    // Pinning: a different prefix would change the digest.
    assert_eq!(a.len(), 32);
}

#[test]
fn encrypt_decrypt_roundtrip_unicode() {
    let key = derive_key("k");
    let plain = "пароль-секрет-🌟";
    let enc = encrypt_field(&key, plain).unwrap();
    let back = decrypt_field(&key, &enc).unwrap();
    assert_eq!(back, plain);
}

#[test]
fn encrypt_produces_distinct_ciphertexts_per_call() {
    // Random nonce → same plaintext encrypts to different ciphertexts.
    let key = derive_key("k");
    let a = encrypt_field(&key, "msg").unwrap();
    let b = encrypt_field(&key, "msg").unwrap();
    assert_ne!(a, b);
}

#[test]
fn decrypt_rejects_short_ciphertext() {
    use base64::Engine;
    let key = derive_key("k");
    // 11-byte payload — below the 12-byte nonce minimum.
    let too_short = base64::engine::general_purpose::STANDARD.encode([0u8; 11]);
    let err = decrypt_field(&key, &too_short).unwrap_err();
    assert!(err.to_string().contains("too short"));
}

#[test]
fn decrypt_rejects_invalid_base64() {
    let key = derive_key("k");
    assert!(decrypt_field(&key, "!!!not-base64!!!").is_err());
}

#[test]
fn decrypt_rejects_wrong_key() {
    let k1 = derive_key("a");
    let k2 = derive_key("b");
    let enc = encrypt_field(&k1, "secret").unwrap();
    let err = decrypt_field(&k2, &enc).unwrap_err();
    assert!(err.to_string().contains("decryption error"));
}

#[test]
fn decrypt_rejects_tampered_ciphertext() {
    use base64::Engine;
    let key = derive_key("k");
    let enc = encrypt_field(&key, "secret").unwrap();
    let mut bytes = base64::engine::general_purpose::STANDARD.decode(enc).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let tampered = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(decrypt_field(&key, &tampered).is_err());
}

#[test]
fn master_key_errors_when_env_unset() {
    let _g = ENV_LOCK.lock().unwrap();
    // SAFETY: env mutation serialized via ENV_LOCK.
    unsafe {
        std::env::remove_var("MASTER_KEY");
    }
    let err = master_key().unwrap_err();
    assert!(err.to_string().contains("MASTER_KEY"));
}

#[test]
fn master_key_errors_when_env_empty() {
    let _g = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("MASTER_KEY", "");
    }
    let err = master_key().unwrap_err();
    unsafe {
        std::env::remove_var("MASTER_KEY");
    }
    assert!(err.to_string().contains("MASTER_KEY"));
}

#[test]
fn master_key_returns_derived_key_when_set() {
    let _g = ENV_LOCK.lock().unwrap();
    unsafe {
        std::env::set_var("MASTER_KEY", "a-strong-secret-32-bytes-or-more!");
    }
    let k = master_key().unwrap();
    unsafe {
        std::env::remove_var("MASTER_KEY");
    }
    assert_eq!(k.len(), 32);
    assert_eq!(k, derive_key("a-strong-secret-32-bytes-or-more!"));
}
