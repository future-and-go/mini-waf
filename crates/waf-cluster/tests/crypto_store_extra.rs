//! Additional coverage for `crypto::store::KeyStore` and the encrypt/decrypt
//! blob helpers — error paths and persistence-to-tempdir.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::redundant_clone,
    clippy::redundant_closure_for_method_calls,
    clippy::field_reassign_with_default,
    clippy::significant_drop_tightening,
    clippy::similar_names,
    clippy::unreadable_literal,
    clippy::approx_constant,
    clippy::doc_markdown,
    clippy::map_unwrap_or
)]

use std::fs;

use waf_cluster::crypto::store::{KeyStore, decrypt_blob, encrypt_blob};

fn unique_path(name: &str) -> std::path::PathBuf {
    let nano = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!("prx-waf-cov-{name}-{nano}.bin"))
}

#[test]
fn keystore_path_accessor() {
    let p = unique_path("path");
    let store = KeyStore::new(p.to_str().unwrap());
    assert_eq!(store.path(), p.to_str().unwrap());
    assert!(!store.exists(), "fresh path must not exist");
}

#[test]
fn keystore_save_creates_parent_dirs() {
    let dir = std::env::temp_dir().join(format!(
        "prx-waf-cov-nested-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let nested = dir.join("a").join("b").join("ca.bin");
    let store = KeyStore::new(nested.to_str().unwrap());
    store.save_ca_key("PEM", "pw").expect("save creates dirs");
    assert!(store.exists());
    let loaded = store.load_ca_key("pw").expect("load");
    assert_eq!(loaded, "PEM");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn keystore_load_missing_file_errors() {
    let p = unique_path("missing");
    let store = KeyStore::new(p.to_str().unwrap());
    let res = store.load_ca_key("pw");
    let err = res.expect_err("missing file errors");
    assert!(format!("{err}").contains("failed to read"));
}

#[test]
fn keystore_load_too_short_file_errors() {
    let p = unique_path("short");
    fs::write(&p, b"abc").expect("write short");
    let store = KeyStore::new(p.to_str().unwrap());
    let res = store.load_ca_key("pw");
    let err = res.expect_err("short file errors");
    assert!(format!("{err}").contains("too short"));
    let _ = fs::remove_file(&p);
}

#[test]
fn keystore_wrong_passphrase_fails() {
    let p = unique_path("wrong-pw");
    let store = KeyStore::new(p.to_str().unwrap());
    store.save_ca_key("secret", "right").expect("save");
    let res = store.load_ca_key("wrong");
    let err = res.expect_err("wrong pw must fail");
    assert!(format!("{err}").contains("wrong passphrase"));
    let _ = fs::remove_file(&p);
}

#[test]
fn encrypt_decrypt_blob_roundtrip() {
    let plain = b"sensitive bytes";
    let enc = encrypt_blob(plain, "pw").expect("enc");
    assert!(enc.len() > plain.len(), "ciphertext includes nonce + tag");
    let dec = decrypt_blob(&enc, "pw").expect("dec");
    assert_eq!(dec, plain);
}

#[test]
fn decrypt_blob_too_short_errors() {
    let res = decrypt_blob(&[0u8; 4], "pw");
    let err = res.expect_err("short blob");
    assert!(format!("{err}").contains("too short"));
}

#[test]
fn decrypt_blob_wrong_passphrase_fails() {
    let enc = encrypt_blob(b"hello", "good").expect("enc");
    let res = decrypt_blob(&enc, "bad");
    let err = res.expect_err("wrong pw");
    assert!(format!("{err}").contains("decryption failed"));
}

#[test]
fn decrypt_blob_tampered_ciphertext_fails() {
    let mut enc = encrypt_blob(b"hi", "pw").expect("enc");
    let last = enc.len() - 1;
    enc[last] ^= 0xff;
    let res = decrypt_blob(&enc, "pw");
    assert!(res.is_err(), "tampered ciphertext must fail GCM auth");
}
