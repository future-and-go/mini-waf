//! FR-003 phase-03 hot-reload integration test.
//!
//! Spawns a `CustomRuleFileWatcher` against a tempdir, writes a yaml file,
//! and asserts the engine sees the new rule within a small timeout. Then
//! removes the file and asserts the rule is wiped.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use waf_engine::rules::custom_file_loader::CustomRuleFileWatcher;
use waf_engine::rules::engine::CustomRulesEngine;

/// Poll `cond` up to `timeout`; returns true if it ever passes.
fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cond() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    cond()
}

const SAMPLE_RULE: &str = r"
kind: custom_rule_v1
id: hr-1
name: hot reload test
conditions:
  - field: path
    operator: eq
    value: /hr
";

#[test]
fn watcher_loads_new_file_then_clears_on_remove() {
    let tmp = tempdir().expect("tempdir");
    // Canonicalize: macOS tempdir returns `/var/folders/...` (a symlink to
    // `/private/var/...`). FSEvents reports events under the canonical path,
    // which can mismatch the watch path otherwise.
    let rules_root = tmp.path().canonicalize().expect("canonicalize");
    // Watcher::spawn will create <rules_root>/custom for us.
    let engine = Arc::new(CustomRulesEngine::new());
    let _watcher = CustomRuleFileWatcher::spawn(rules_root.clone(), Arc::clone(&engine)).expect("spawn watcher");

    let custom_dir = rules_root.join("custom");
    let rule_path = custom_dir.join("hr.yaml");

    // Give the OS-level watcher a moment to fully attach before mutating.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(engine.len(), 0);

    // Write file → debounced reload should pick it up.
    std::fs::write(&rule_path, SAMPLE_RULE).expect("write rule");
    assert!(
        wait_until(Duration::from_secs(3), || engine.len() == 1),
        "rule should appear after write (len={})",
        engine.len()
    );

    // Remove → reload should wipe the file rule.
    std::fs::remove_file(&rule_path).expect("remove rule");
    assert!(
        wait_until(Duration::from_secs(3), || engine.is_empty()),
        "rule should be cleared after remove (len={})",
        engine.len()
    );
}
