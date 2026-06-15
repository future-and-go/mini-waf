//! Integration tests for `load_config` — TOML parsing, validation, env-overrides.
//!
//! Uses `tempfile` to avoid polluting the repo and avoids `MASTER_KEY` /
//! `CACHE_BACKEND` collisions by serializing env-var tests via
//! `std::sync::Mutex`.

#![allow(
    unsafe_code,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::undocumented_unsafe_blocks,
    clippy::indexing_slicing,
    clippy::print_stderr
)]

use std::io::Write;
use std::sync::Mutex;
use tempfile::NamedTempFile;
use waf_common::config::{AppConfig, CacheBackendKind, load_config};

// `cargo test` runs tests within a binary on multiple threads; env
// mutation must serialize.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn load_minimal_valid_config() {
    let _g = ENV_LOCK.lock().unwrap();
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        r#"
[proxy]
listen_addr = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"

[api]
listen_addr = "127.0.0.1:9527"

[storage]
database_url = "postgresql://u:p@127.0.0.1/db"
max_connections = 5
"#
    )
    .unwrap();
    let cfg = load_config(f.path().to_str().unwrap()).expect("must load");
    assert_eq!(cfg.storage.max_connections, 5);
}

#[test]
fn load_config_missing_file_errors() {
    let r = load_config("/this/path/should/not/exist.toml");
    assert!(r.is_err());
}

#[test]
fn load_minimal_valid_yaml() {
    let _g = ENV_LOCK.lock().unwrap();
    let mut f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    write!(
        f,
        "proxy:\n  listen_addr: \"0.0.0.0:80\"\n  listen_addr_tls: \"0.0.0.0:443\"\napi:\n  listen_addr: \"127.0.0.1:9527\"\nstorage:\n  database_url: \"postgresql://u:p@127.0.0.1/db\"\n  max_connections: 7\n"
    )
    .unwrap();
    let cfg = load_config(f.path().to_str().unwrap()).expect("yaml must load");
    assert_eq!(cfg.storage.max_connections, 7);
}

#[test]
fn yaml_and_toml_load_to_same_effective_config() {
    let _g = ENV_LOCK.lock().unwrap();

    let mut toml_f = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
    writeln!(
        toml_f,
        r#"
[proxy]
listen_addr = "0.0.0.0:8080"
listen_addr_tls = "0.0.0.0:8443"
[api]
listen_addr = "127.0.0.1:9527"
[storage]
database_url = "postgresql://u:p@127.0.0.1/db"
max_connections = 9
"#
    )
    .unwrap();

    let mut yaml_f = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
    write!(
        yaml_f,
        "proxy:\n  listen_addr: \"0.0.0.0:8080\"\n  listen_addr_tls: \"0.0.0.0:8443\"\napi:\n  listen_addr: \"127.0.0.1:9527\"\nstorage:\n  database_url: \"postgresql://u:p@127.0.0.1/db\"\n  max_connections: 9\n"
    )
    .unwrap();

    let from_toml = load_config(toml_f.path().to_str().unwrap()).expect("toml load");
    let from_yaml = load_config(yaml_f.path().to_str().unwrap()).expect("yaml load");

    assert_eq!(from_toml.storage.max_connections, from_yaml.storage.max_connections);
    assert_eq!(from_toml.proxy.listen_addr, from_yaml.proxy.listen_addr);
    assert_eq!(from_toml.proxy.listen_addr_tls, from_yaml.proxy.listen_addr_tls);
}

#[test]
fn load_config_bad_toml_errors() {
    let mut f = NamedTempFile::new().unwrap();
    writeln!(f, "this is = not valid toml = at all").unwrap();
    let r = load_config(f.path().to_str().unwrap());
    assert!(r.is_err());
}

#[test]
fn load_repo_default_toml() {
    let _g = ENV_LOCK.lock().unwrap();
    // Walk up from this crate's dir to repo root and load configs/default.toml.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let candidate = manifest.join("../../configs/default.toml");
    if !candidate.exists() {
        // Worktree may have been re-rooted; skip rather than fail spuriously.
        eprintln!("default.toml not present at {candidate:?}; skipping");
        return;
    }
    let cfg = load_config(candidate.to_str().unwrap()).expect("default.toml must load");
    assert!(cfg.cache.enabled);
}

#[test]
fn cache_backend_env_override_applies() {
    let _g = ENV_LOCK.lock().unwrap();
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        r#"
[proxy]
listen_addr = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"
[api]
listen_addr = "127.0.0.1:9527"
[storage]
database_url = "x"
max_connections = 1
"#
    )
    .unwrap();

    // SAFETY: env mutation serialized via ENV_LOCK; std::env::set_var is
    // safe here because no other thread reads CACHE_BACKEND while we hold
    // the lock.
    unsafe {
        std::env::set_var("CACHE_BACKEND", "embedded");
    }
    let cfg = load_config(f.path().to_str().unwrap()).expect("must load");
    assert_eq!(cfg.cache.backend, CacheBackendKind::Embedded);
    unsafe {
        std::env::remove_var("CACHE_BACKEND");
    }
}

#[test]
fn cache_backend_env_override_invalid_rejected() {
    let _g = ENV_LOCK.lock().unwrap();
    let mut f = NamedTempFile::new().unwrap();
    writeln!(
        f,
        r#"
[proxy]
listen_addr = "0.0.0.0:80"
listen_addr_tls = "0.0.0.0:443"
[api]
listen_addr = "127.0.0.1:9527"
[storage]
database_url = "x"
max_connections = 1
"#
    )
    .unwrap();
    unsafe {
        std::env::set_var("CACHE_BACKEND", "redis-cluster-thing");
    }
    let r = load_config(f.path().to_str().unwrap());
    unsafe {
        std::env::remove_var("CACHE_BACKEND");
    }
    assert!(r.is_err());
    assert!(r.unwrap_err().to_string().contains("CACHE_BACKEND"));
}

#[test]
fn app_config_round_trip_via_toml() {
    let _g = ENV_LOCK.lock().unwrap();
    let cfg = AppConfig::default();
    let s = toml::to_string(&cfg).expect("serialize");
    // Defaults should round-trip back through load.
    let mut f = NamedTempFile::new().unwrap();
    write!(f, "{s}").unwrap();
    let back = load_config(f.path().to_str().unwrap()).expect("reload");
    assert_eq!(back.storage.max_connections, cfg.storage.max_connections);
    assert_eq!(back.cache.backend, cfg.cache.backend);
}
