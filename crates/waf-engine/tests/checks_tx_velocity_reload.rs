//! Coverage for `checks::tx_velocity::config::TxVelocityReloader` —
//! exercises the `notify` background watcher (debounce, reload, fail-soft).
//! Mirrors patterns from `access_hot_reload.rs` so review surface stays small.

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
    clippy::needless_raw_string_hashes
)]

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use waf_engine::checks::tx_velocity::{TxVelocityConfig, TxVelocityFileConfig, TxVelocityReloader};

const V1_INERT: &str = "tx_velocity:\n  enabled: false\n";
const V2_ENABLED: &str = r#"tx_velocity:
  enabled: true
  session_cookie: "TXSID"
  endpoint_roles:
    - role: login
      path: "^/login$"
"#;
const BAD_YAML: &str = r#"tx_velocity:
  enabled: true
  endpoint_roles:
    - role: login
      path: ""
"#;

const DEBOUNCE_MS: u64 = 80;
const SETTLE: Duration = Duration::from_millis(700);

#[test]
fn t_reload_swaps_on_change() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("tx-velocity.yaml");
    std::fs::write(&path, V1_INERT).expect("write v1");

    let initial = TxVelocityFileConfig::from_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<TxVelocityConfig>> = Arc::new(ArcSwap::from(initial));
    assert!(!store.load().enabled, "baseline disabled");

    let _r = TxVelocityReloader::start(path.clone(), Arc::clone(&store), Some(DEBOUNCE_MS)).expect("spawn");

    std::fs::write(&path, V2_ENABLED).expect("write v2");
    std::thread::sleep(SETTLE);

    let snap = store.load();
    assert!(snap.enabled, "v2 enabled should be live after reload");
    assert_eq!(snap.session_cookie, "TXSID");
}

#[test]
fn t_reload_keeps_prior_on_bad_yaml() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("tx-velocity.yaml");
    std::fs::write(&path, V2_ENABLED).expect("write v2");

    let initial = TxVelocityFileConfig::from_path(&path).expect("v2 parse");
    let store: Arc<ArcSwap<TxVelocityConfig>> = Arc::new(ArcSwap::from(initial));
    assert!(store.load().enabled, "baseline enabled");

    let _r = TxVelocityReloader::start(path.clone(), Arc::clone(&store), Some(DEBOUNCE_MS)).expect("spawn");

    std::fs::write(&path, BAD_YAML).expect("write bad");
    std::thread::sleep(SETTLE);

    assert!(
        store.load().enabled,
        "bad reload must be ignored; previous snapshot retained"
    );
}

#[test]
fn t_reload_default_debounce_when_none() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("tx-velocity.yaml");
    std::fs::write(&path, V1_INERT).expect("write v1");

    let initial = TxVelocityFileConfig::from_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<TxVelocityConfig>> = Arc::new(ArcSwap::from(initial));

    // None ⇒ exercises the unwrap_or(DEFAULT_DEBOUNCE_MS) branch.
    let _r = TxVelocityReloader::start(path.clone(), Arc::clone(&store), None).expect("spawn");

    std::fs::write(&path, V2_ENABLED).expect("write v2");
    // Default debounce is 200ms; allow extra time.
    std::thread::sleep(Duration::from_millis(900));

    assert!(store.load().enabled, "default-debounce reload must complete");
}

#[test]
fn t_from_path_reports_io_error() {
    let path = std::path::PathBuf::from("/nonexistent/no-such.yaml");
    let err = TxVelocityFileConfig::from_path(&path).unwrap_err().to_string();
    assert!(err.contains("tx_velocity"), "got: {err}");
}

#[test]
fn t_validate_session_cookie_empty_rejected() {
    let yaml = r#"tx_velocity:
  enabled: true
  session_cookie: ""
"#;
    assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
}

#[test]
fn t_validate_session_ttl_zero_rejected() {
    let yaml = r#"tx_velocity:
  enabled: true
  session_ttl_secs: 0
"#;
    assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
}

#[test]
fn t_validate_janitor_period_zero_rejected() {
    let yaml = r#"tx_velocity:
  enabled: true
  janitor_period_secs: 0
"#;
    assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
}

#[test]
fn t_validate_nested_plus_quantifier_rejected() {
    let yaml = r#"tx_velocity:
  enabled: true
  endpoint_roles:
    - role: login
      path: "(.+)+evil"
"#;
    assert!(TxVelocityFileConfig::from_yaml_str(yaml).is_err());
}

#[test]
fn t_default_runtime_config_inert() {
    let cfg = TxVelocityConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.session_cookie, "SESSIONID");
    assert_eq!(cfg.signal_cooldown_ms, 5_000);
    assert_eq!(cfg.session_ttl_secs, 600);
    assert_eq!(cfg.janitor_period_secs, 60);
}
