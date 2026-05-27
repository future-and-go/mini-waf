//! Config sync tests — build, apply, version skip, and partial config.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use waf_cluster::protocol::ConfigSync;
use waf_cluster::sync::config::{ConfigSyncer, SyncableConfig};
use waf_common::config::{ApiConfig, CacheConfig, ProxyConfig, RulesConfig};

fn sample_syncable_config() -> SyncableConfig {
    SyncableConfig {
        proxy: ProxyConfig {
            listen_addr: "0.0.0.0:8080".into(),
            ..Default::default()
        },
        rules: RulesConfig::default(),
        cache: CacheConfig::default(),
        api: ApiConfig {
            listen_addr: "0.0.0.0:9527".into(),
        },
    }
}

#[test]
fn build_sync_produces_valid_toml() {
    let mut syncer = ConfigSyncer::new("main-1".into());
    let config = sample_syncable_config();
    let msg = syncer.build_sync(&config).unwrap();

    assert_eq!(msg.version, 1);
    assert!(!msg.config_toml.is_empty());

    // Parse it back
    let parsed: SyncableConfig = toml::from_str(&msg.config_toml).unwrap();
    assert_eq!(parsed.proxy.listen_addr, "0.0.0.0:8080");
    assert_eq!(parsed.api.listen_addr, "0.0.0.0:9527");
}

#[test]
fn apply_sync_updates_version_and_returns_config() {
    let mut syncer = ConfigSyncer::new("worker-1".into());
    let config = sample_syncable_config();

    let mut builder = ConfigSyncer::new("main-1".into());
    let msg = builder.build_sync(&config).unwrap();

    let result = syncer.apply_sync(&msg, 1);
    assert!(result.is_some());
    assert_eq!(syncer.current_version(), 1);

    let applied = result.unwrap();
    assert_eq!(applied.proxy.listen_addr, "0.0.0.0:8080");
}

#[test]
fn version_skip_noop_when_already_current() {
    let mut syncer = ConfigSyncer::new("worker-1".into());

    // Apply version 1
    let msg1 = ConfigSync {
        version: 1,
        config_toml: toml::to_string(&sample_syncable_config()).unwrap(),
    };
    let r1 = syncer.apply_sync(&msg1, 1);
    assert!(r1.is_some());

    // Send version 1 again — should be skipped
    let r2 = syncer.apply_sync(&msg1, 1);
    assert!(r2.is_none());
    assert_eq!(syncer.current_version(), 1);
}

#[test]
fn version_skip_applies_newer_version() {
    let mut syncer = ConfigSyncer::new("worker-1".into());

    // Apply version 5
    let msg5 = ConfigSync {
        version: 5,
        config_toml: toml::to_string(&sample_syncable_config()).unwrap(),
    };
    syncer.apply_sync(&msg5, 1);
    assert_eq!(syncer.current_version(), 5);

    // Version 7 should apply
    let msg7 = ConfigSync {
        version: 7,
        config_toml: toml::to_string(&sample_syncable_config()).unwrap(),
    };
    let r = syncer.apply_sync(&msg7, 1);
    assert!(r.is_some());
    assert_eq!(syncer.current_version(), 7);
}

#[test]
fn invalid_toml_rejected_gracefully() {
    let mut syncer = ConfigSyncer::new("worker-1".into());

    let msg = ConfigSync {
        version: 1,
        config_toml: "this is not valid toml {{{{".into(),
    };

    let result = syncer.apply_sync(&msg, 1);
    assert!(result.is_none());
    // Version should not have changed
    assert_eq!(syncer.current_version(), 0);
}

#[test]
fn partial_config_does_not_include_cluster_or_storage() {
    let config = sample_syncable_config();
    let toml_str = toml::to_string(&config).unwrap();

    // SyncableConfig should not contain cluster or storage sections
    assert!(!toml_str.contains("[cluster]"));
    assert!(!toml_str.contains("[storage]"));
    assert!(!toml_str.contains("database_url"));

    // But should contain the syncable sections
    assert!(toml_str.contains("[proxy]"));
    assert!(toml_str.contains("[api]"));
}

#[test]
fn build_sync_increments_version() {
    let mut syncer = ConfigSyncer::new("main-1".into());
    let config = sample_syncable_config();

    let m1 = syncer.build_sync(&config).unwrap();
    let m2 = syncer.build_sync(&config).unwrap();
    let m3 = syncer.build_sync(&config).unwrap();

    assert_eq!(m1.version, 1);
    assert_eq!(m2.version, 2);
    assert_eq!(m3.version, 3);
    assert_eq!(syncer.current_version(), 3);
}
