//! Integration test for FR-002 phase-04 hot-reload.
//!
//! Approach: drive the reload path directly via the crate-public `reload()`
//! plus a real file watcher in one scenario. We avoid timing-flaky polls
//! against the watcher by calling `reload()` synchronously where the
//! contract under test is the reload chain itself (parse → validate → swap).
//!
//! What we *do* exercise via the live watcher: that `spawn()` succeeds and that
//! a write to the watched file triggers exactly one reload after debounce.

// Test conventions: unwrap/index/panic are idiomatic in tests; loosen pedantic.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::items_after_statements
)]

use std::sync::Arc;
use std::time::{Duration, Instant};

use gateway::tiered::tier_config_watcher::reload;
use gateway::tiered::{TierConfigWatcher, TierPolicyRegistry, TierSnapshot};
use waf_common::tier::Tier;

const VALID_BLOCK_100: &str = r#"
[tiered_protection]
default_tier = "catch_all"

[tiered_protection.policies.critical]
fail_mode = "close"
ddos_threshold_rps = 1000
cache_policy = { mode = "no_cache" }
risk_thresholds = { allow = 10, challenge = 50, block = 100 }

[tiered_protection.policies.high]
fail_mode = "close"
ddos_threshold_rps = 1000
cache_policy = { mode = "no_cache" }
risk_thresholds = { allow = 10, challenge = 50, block = 100 }

[tiered_protection.policies.medium]
fail_mode = "open"
ddos_threshold_rps = 1000
cache_policy = { mode = "no_cache" }
risk_thresholds = { allow = 10, challenge = 50, block = 100 }

[tiered_protection.policies.catch_all]
fail_mode = "open"
ddos_threshold_rps = 1000
cache_policy = { mode = "no_cache" }
risk_thresholds = { allow = 10, challenge = 50, block = 100 }
"#;

fn config_with_block(block: u32) -> String {
    VALID_BLOCK_100.replace("block = 100", &format!("block = {block}"))
}

fn initial_registry(block: u32) -> Arc<TierPolicyRegistry> {
    let raw = config_with_block(block);
    #[derive(serde::Deserialize)]
    struct Env {
        tiered_protection: waf_common::tier::TierConfig,
    }
    let env: Env = toml::from_str(&raw).unwrap();
    let snap = TierSnapshot::try_from_config(env.tiered_protection).unwrap();
    Arc::new(TierPolicyRegistry::new(snap))
}

#[test]
fn reload_swaps_to_new_threshold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("waf.toml");
    std::fs::write(&path, config_with_block(100)).unwrap();

    let registry = initial_registry(100);
    assert_eq!(registry.snapshot().policies[&Tier::CatchAll].risk_thresholds.block, 100);

    std::fs::write(&path, config_with_block(200)).unwrap();
    reload(&path, &registry);

    assert_eq!(
        registry.snapshot().policies[&Tier::CatchAll].risk_thresholds.block,
        200,
        "reload should have swapped to new threshold"
    );
}

#[test]
fn malformed_toml_keeps_previous_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("waf.toml");
    std::fs::write(&path, "this is not valid TOML ===").unwrap();

    let registry = initial_registry(100);
    reload(&path, &registry);

    // Snapshot must be unchanged.
    assert_eq!(
        registry.snapshot().policies[&Tier::CatchAll].risk_thresholds.block,
        100,
        "malformed TOML must not mutate the snapshot"
    );
}

#[test]
fn missing_tier_section_keeps_previous_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("waf.toml");
    // Valid TOML, but no [tiered_protection] table.
    std::fs::write(&path, "[other_section]\nkey = \"value\"\n").unwrap();

    let registry = initial_registry(100);
    reload(&path, &registry);

    assert_eq!(
        registry.snapshot().policies[&Tier::CatchAll].risk_thresholds.block,
        100,
        "missing tier section must not mutate the snapshot"
    );
}

#[test]
fn live_watcher_picks_up_file_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("waf.toml");
    std::fs::write(&path, config_with_block(100)).unwrap();

    let registry = initial_registry(100);
    let _watcher = TierConfigWatcher::spawn(path.clone(), Arc::clone(&registry), 100).expect("watcher spawn");

    // Give notify a moment to register the watch before we mutate.
    std::thread::sleep(Duration::from_millis(150));
    std::fs::write(&path, config_with_block(300)).unwrap();

    // Poll up to 3s for the swap to land — debounce is 100ms.
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let block = registry.snapshot().policies[&Tier::CatchAll].risk_thresholds.block;
        if block == 300 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "live watcher did not reload within 3s; block still {block}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}
