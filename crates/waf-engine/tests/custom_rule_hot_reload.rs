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
    clippy::missing_const_for_fn,
    clippy::needless_raw_string_hashes
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
        device_fp: None,
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

/// Verifies that modifying a `.data` file referenced by a `pm_from_file` rule
/// causes the engine to pick up new patterns after a fresh load (DataFileRegistry
/// mtime invalidation).
#[test]
fn data_file_reload_picks_up_new_pattern() {
    use waf_engine::OWASPCheck;
    use waf_engine::checks::Check;

    let tmp = tempdir().expect("tempdir");
    let rules_root = tmp.path().canonicalize().expect("canonicalize");

    // Create the data/ subdirectory with a .data file
    let data_dir = rules_root.join("data");
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let data_file = data_dir.join("test.data");
    std::fs::write(&data_file, "forbidden\n").expect("write initial data");

    // Write a YAML rule using pm_from_file pointing to test.data
    let rule_yaml = r#"
kind: custom_rule_v1
id: HR-DATA-1
name: hot reload data file test
enabled: true
action: block
pattern_field: path
operator: pm_from_file
value: test.data
category: test
severity: critical
paranoia: 1
"#;
    std::fs::write(rules_root.join("hr-data.yaml"), rule_yaml).expect("write rule yaml");

    // Load engine — should block /forbidden
    let checker = OWASPCheck::from_directory(&rules_root);
    assert!(checker.rule_count() > 0, "should load at least 1 rule");

    let host_config = Arc::new(HostConfig {
        code: "test".into(),
        host: "example.com".into(),
        defense_config: waf_common::DefenseConfig {
            owasp_set: true,
            owasp_paranoia: 4,
            ..Default::default()
        },
        ..HostConfig::default()
    });

    let ctx_forbidden = RequestCtx {
        req_id: "hr-d1".into(),
        client_ip: "1.2.3.4".parse().unwrap(),
        client_port: 0,
        method: "GET".into(),
        host: "example.com".into(),
        port: 80,
        path: "/forbidden".into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: Arc::clone(&host_config),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
    };
    assert!(
        checker.check(&ctx_forbidden).is_some(),
        "GET /forbidden must be blocked by pm_from_file rule"
    );

    // /newbad should NOT be blocked yet
    let ctx_newbad = RequestCtx {
        path: "/newbad".into(),
        req_id: "hr-d2".into(),
        ..ctx_forbidden.clone()
    };
    assert!(
        checker.check(&ctx_newbad).is_none(),
        "GET /newbad must pass — not in data file yet"
    );

    // Append "newbad" to the data file
    std::fs::write(&data_file, "forbidden\nnewbad\n").expect("update data file");

    // Sleep briefly to ensure file mtime changes
    std::thread::sleep(Duration::from_millis(100));

    // Re-load the engine (simulates what hot reload would do)
    let checker2 = OWASPCheck::from_directory(&rules_root);
    assert!(
        checker2.check(&ctx_newbad).is_some(),
        "GET /newbad must be blocked after data file update and re-load"
    );
}
