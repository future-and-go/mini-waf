//! FR-006 — Challenge configuration integration tests.
//!
//! Tests YAML config loading, defaults, hot-reload, and conversion to runtime types.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::disallowed_types,
    clippy::disallowed_methods,
    clippy::missing_docs_in_private_items
)]

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tempfile::tempdir;
use waf_engine::challenge::{ChallengeConfig, ChallengeReloader, DEFAULT_DEBOUNCE_MS, DifficultyMap};

#[test]
fn config_load_valid_yaml() {
    let yaml = r#"
challenge:
  enabled: true
  type: js_challenge
  difficulty:
    default: 16
    tiers:
      - min_risk: 30
        max_risk: 50
        difficulty: 14
  token:
    ttl_secs: 300
    cookie_name: __waf_cc
    cookie_max_age: 300
    same_site: Strict
    http_only: false
  branding:
    title: Security Verification
    message: Please wait while we verify your browser...
  nonce_store:
    capacity: 50000
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("challenge.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();

    assert!(config.enabled);
    assert_eq!(config.challenge_type, "js_challenge");
    assert_eq!(config.difficulty.default, 16);
    assert_eq!(config.difficulty.tiers.len(), 1);
    assert_eq!(config.difficulty.tiers[0].min_risk, 30);
    assert_eq!(config.difficulty.tiers[0].max_risk, 50);
    assert_eq!(config.difficulty.tiers[0].difficulty, 14);
    assert_eq!(config.token.ttl_secs, 300);
    assert_eq!(config.token.cookie_name, "__waf_cc");
    assert_eq!(config.branding.title, "Security Verification");
    assert_eq!(config.nonce_store.capacity, 50000);
}

#[test]
fn config_defaults_applied() {
    let yaml = r#"
challenge:
  difficulty:
    default: 12
    tiers: []
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("minimal.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();

    assert!(config.enabled, "enabled defaults to true");
    assert_eq!(config.challenge_type, "js_challenge", "type defaults to js_challenge");
    assert_eq!(config.token.ttl_secs, 300, "ttl_secs defaults to 300");
    assert_eq!(config.token.cookie_name, "__waf_cc", "cookie_name defaults to __waf_cc");
    assert_eq!(config.token.same_site, "Strict", "same_site defaults to Strict");
    assert!(!config.token.http_only, "http_only defaults to false");
    assert_eq!(config.branding.title, "Security Check", "title defaults");
    assert_eq!(config.nonce_store.capacity, 100_000, "capacity defaults to 100000");
}

#[test]
fn config_disabled_challenge() {
    let yaml = r#"
challenge:
  enabled: false
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("disabled.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();
    assert!(!config.enabled);
}

#[test]
fn difficulty_config_converts_to_map() {
    let yaml = r#"
challenge:
  difficulty:
    default: 14
    tiers:
      - min_risk: 50
        max_risk: 70
        difficulty: 18
      - min_risk: 70
        max_risk: 90
        difficulty: 20
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("tiers.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();
    let map: DifficultyMap = (&config.difficulty).into();

    assert_eq!(map.default, 14);
    assert_eq!(map.tiers.len(), 2);

    assert_eq!(map.difficulty_for_risk(40), 14, "below tiers -> default");
    assert_eq!(map.difficulty_for_risk(60), 18, "50-70 -> tier 1");
    assert_eq!(map.difficulty_for_risk(80), 20, "70-90 -> tier 2");
    assert_eq!(map.difficulty_for_risk(95), 14, "above tiers -> default");
}

#[test]
fn config_to_difficulty_map_method() {
    let config = ChallengeConfig::default();
    let map = config.to_difficulty_map();

    assert_eq!(map.default, 16);
    assert_eq!(map.tiers.len(), 3);
    assert_eq!(map.difficulty_for_risk(35), 14);
}

#[test]
fn config_load_error_on_missing_file() {
    let result = ChallengeConfig::from_path(std::path::Path::new("/nonexistent/path.yaml"));
    assert!(result.is_err());
}

#[test]
fn config_load_error_on_invalid_yaml() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("invalid.yaml");
    std::fs::write(&path, "not: [valid: yaml").unwrap();

    let result = ChallengeConfig::from_path(&path);
    assert!(result.is_err());
}

#[test]
fn config_load_error_on_wrong_structure() {
    let yaml = r#"
not_challenge:
  something: else
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("wrong.yaml");
    std::fs::write(&path, yaml).unwrap();

    let result = ChallengeConfig::from_path(&path);
    assert!(result.is_err());
}

#[test]
fn hot_reload_updates_config() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("challenge.yaml");
    std::fs::write(&path, "challenge:\n  enabled: true\n").unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();
    let swap = Arc::new(ArcSwap::from(config));
    assert!(swap.load().enabled, "initial config should be enabled");

    let _reloader = ChallengeReloader::start(path.clone(), Arc::clone(&swap), 50).unwrap();

    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "challenge:\n  enabled: false\n").unwrap();
    f.sync_all().unwrap();
    drop(f);

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if !swap.load().enabled {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("hot reload never observed enabled=false");
}

#[test]
fn hot_reload_keeps_previous_on_invalid() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("challenge.yaml");
    std::fs::write(&path, "challenge:\n  enabled: true\n  difficulty:\n    default: 10\n").unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();
    let swap = Arc::new(ArcSwap::from(config));
    assert!(swap.load().enabled);
    assert_eq!(swap.load().difficulty.default, 10);

    let _reloader = ChallengeReloader::start(path.clone(), Arc::clone(&swap), 50).unwrap();

    std::fs::write(&path, "challenge:\n  difficulty:\n    default: not_a_number\n").unwrap();
    std::thread::sleep(Duration::from_millis(400));

    assert!(swap.load().enabled, "previous config should be retained");
    assert_eq!(swap.load().difficulty.default, 10, "previous difficulty retained");
}

#[test]
fn hot_reload_updates_difficulty() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("challenge.yaml");
    std::fs::write(&path, "challenge:\n  difficulty:\n    default: 12\n").unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();
    let swap = Arc::new(ArcSwap::from(config));
    assert_eq!(swap.load().difficulty.default, 12);

    let _reloader = ChallengeReloader::start(path.clone(), Arc::clone(&swap), 50).unwrap();

    let mut f = std::fs::File::create(&path).unwrap();
    writeln!(f, "challenge:\n  difficulty:\n    default: 20\n").unwrap();
    f.sync_all().unwrap();
    drop(f);

    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if swap.load().difficulty.default == 20 {
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("hot reload never updated difficulty to 20");
}

#[test]
fn default_debounce_constant() {
    assert_eq!(DEFAULT_DEBOUNCE_MS, 200, "default debounce should be 200ms");
}

#[test]
fn config_all_token_options() {
    let yaml = r#"
challenge:
  token:
    ttl_secs: 600
    cookie_name: custom_cc
    cookie_max_age: 1800
    same_site: Lax
    http_only: true
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("token.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();

    assert_eq!(config.token.ttl_secs, 600);
    assert_eq!(config.token.cookie_name, "custom_cc");
    assert_eq!(config.token.cookie_max_age, 1800);
    assert_eq!(config.token.same_site, "Lax");
    assert!(config.token.http_only);
}

#[test]
fn config_branding_options() {
    let yaml = r#"
challenge:
  branding:
    title: Custom Title Here
    message: Custom message for users
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("branding.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();

    assert_eq!(config.branding.title, "Custom Title Here");
    assert_eq!(config.branding.message, "Custom message for users");
}

#[test]
fn config_multiple_tiers() {
    let yaml = r#"
challenge:
  difficulty:
    default: 16
    tiers:
      - min_risk: 0
        max_risk: 30
        difficulty: 10
      - min_risk: 30
        max_risk: 50
        difficulty: 14
      - min_risk: 50
        max_risk: 70
        difficulty: 18
      - min_risk: 70
        max_risk: 100
        difficulty: 22
"#;

    let dir = tempdir().unwrap();
    let path = dir.path().join("multi_tier.yaml");
    std::fs::write(&path, yaml).unwrap();

    let config = ChallengeConfig::from_path(&path).unwrap();
    let map = config.to_difficulty_map();

    assert_eq!(map.difficulty_for_risk(15), 10);
    assert_eq!(map.difficulty_for_risk(40), 14);
    assert_eq!(map.difficulty_for_risk(60), 18);
    assert_eq!(map.difficulty_for_risk(85), 22);
}

#[test]
fn default_config_struct() {
    let config = ChallengeConfig::default();

    assert!(config.enabled);
    assert_eq!(config.challenge_type, "js_challenge");
    assert_eq!(config.difficulty.default, 16);
    assert_eq!(config.difficulty.tiers.len(), 3);
    assert_eq!(config.token.ttl_secs, 300);
    assert_eq!(config.token.cookie_name, "__waf_cc");
    assert_eq!(config.token.cookie_max_age, 300);
    assert_eq!(config.token.same_site, "Strict");
    assert!(!config.token.http_only);
    assert_eq!(config.branding.title, "Security Check");
    assert_eq!(config.nonce_store.capacity, 100_000);
}
