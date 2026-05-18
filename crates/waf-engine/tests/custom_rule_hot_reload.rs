//! FR-003 phase-03 hot-reload integration test.
//!
//! Spawns a `CustomRuleFileWatcher` against a tempdir, writes a yaml file,
//! and asserts the engine sees the new rule within a small timeout. Then
//! removes the file and asserts the rule is wiped.

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
    clippy::missing_docs_in_private_items,
    clippy::doc_markdown,
    clippy::missing_const_for_fn
)]

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use tempfile::tempdir;
use waf_common::{HostConfig, RequestCtx};
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

const PATTERN_RULE: &str = r#"
kind: custom_rule_v1
id: hr-pattern-1
name: SSRF pattern hot-reload test
pattern: "169\\.254\\.169\\.254"
pattern_field: body
action: block
"#;

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

#[test]
fn watcher_loads_pattern_based_rule() {
    let tmp = tempdir().expect("tempdir");
    let rules_root = tmp.path().canonicalize().expect("canonicalize");
    let engine = Arc::new(CustomRulesEngine::new());
    let _watcher = CustomRuleFileWatcher::spawn(rules_root.clone(), Arc::clone(&engine)).expect("spawn watcher");

    let custom_dir = rules_root.join("custom");
    let rule_path = custom_dir.join("pattern-ssrf.yaml");

    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(engine.len(), 0);

    // Write a pattern-based rule (regex, not conditions)
    std::fs::write(&rule_path, PATTERN_RULE).expect("write pattern rule");
    assert!(
        wait_until(Duration::from_secs(3), || engine.len() == 1),
        "pattern rule should appear after write (len={})",
        engine.len()
    );

    // Verify the pattern rule actually matches a request
    let host_config = Arc::new(HostConfig {
        code: "*".into(),
        host: "example.com".into(),
        ..HostConfig::default()
    });
    let ctx = RequestCtx {
        req_id: "hr-pat".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 12345,
        method: "POST".into(),
        host: "example.com".into(),
        port: 80,
        path: "/api".into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::from("url=http://169.254.169.254/latest/meta-data/"),
        content_length: 43,
        is_tls: false,
        host_config,
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
    };
    let hit = engine.check(&ctx);
    assert!(hit.is_some(), "pattern rule should match SSRF payload");

    // Remove → should clear
    std::fs::remove_file(&rule_path).expect("remove pattern rule");
    assert!(
        wait_until(Duration::from_secs(3), || engine.is_empty()),
        "pattern rule should be cleared after remove (len={})",
        engine.len()
    );
}
