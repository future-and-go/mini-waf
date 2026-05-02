//! FR-009 Phase 3 — integration test for `rules/cache.yaml` hot reload.
//!
//! Pattern mirrors `tier_hot_reload.rs`: drive the public `reload()` directly
//! to assert the parse → compile → swap chain, and separately spawn the live
//! watcher to confirm a file write triggers exactly one reload after debounce.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::items_after_statements,
    clippy::manual_assert
)]

use std::time::{Duration, Instant};

use gateway::cache::watcher::{load_or_empty, reload};
use gateway::cache::{CacheRuleWatcher, CompiledRuleSet, RuleSetHolder};

const VALID_30S: &str = r"
version: 1
rules:
  - id: r1
    match:
      path: { prefix: /static/ }
    ttl_seconds: 30
    tags: [static]
";

const VALID_900S: &str = r"
version: 1
rules:
  - id: r1
    match:
      path: { prefix: /static/ }
    ttl_seconds: 900
    tags: [static]
";

const BAD_YAML: &str = "version: ohno\n";

fn ttl_of_first_rule(set: &CompiledRuleSet) -> u64 {
    set.rules
        .first()
        .map(|r| r.ttl.as_secs())
        .expect("ruleset has at least one rule")
}

#[test]
fn reload_swaps_in_new_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.yaml");
    std::fs::write(&path, VALID_30S).unwrap();

    let initial = load_or_empty(&path).unwrap();
    assert_eq!(ttl_of_first_rule(&initial), 30);
    let holder = RuleSetHolder::new(initial);

    std::fs::write(&path, VALID_900S).unwrap();
    reload(&path, &holder);
    assert_eq!(ttl_of_first_rule(&holder.load()), 900);
}

#[test]
fn reload_keeps_prior_on_bad_yaml() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.yaml");
    std::fs::write(&path, VALID_30S).unwrap();

    let initial = load_or_empty(&path).unwrap();
    let holder = RuleSetHolder::new(initial);

    std::fs::write(&path, BAD_YAML).unwrap();
    reload(&path, &holder);
    // Prior 30s ruleset must still serve.
    assert_eq!(ttl_of_first_rule(&holder.load()), 30);
}

#[test]
fn watcher_triggers_reload_on_file_write() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("cache.yaml");
    std::fs::write(&path, VALID_30S).unwrap();

    let initial = load_or_empty(&path).unwrap();
    let holder = RuleSetHolder::new(initial);

    // Short debounce keeps the test fast but stable on slow CI.
    let _watcher = CacheRuleWatcher::spawn(path.clone(), holder.clone(), 50).expect("watcher spawns");

    // Give the OS watcher time to register before the first write — flake guard.
    std::thread::sleep(Duration::from_millis(150));
    std::fs::write(&path, VALID_900S).unwrap();

    // Poll up to 5s for the swap to land.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if ttl_of_first_rule(&holder.load()) == 900 {
            return;
        }
        if Instant::now() > deadline {
            panic!(
                "watcher did not reload within 5s; current TTL={}",
                ttl_of_first_rule(&holder.load())
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}
