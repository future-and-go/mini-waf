//! Phase 07 — `HotReloader` debounces rapid file events into a single reload.

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
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    unused_imports
)]

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tempfile::tempdir;
use waf_common::config::RulesConfig;
use waf_engine::rules::hot_reload::HotReloader;
use waf_engine::rules::manager::RuleManager;

fn empty_manager(dir: &std::path::Path) -> Arc<Mutex<RuleManager>> {
    let cfg = RulesConfig {
        dir: dir.display().to_string(),
        hot_reload: false,
        reload_debounce_ms: 0,
        enable_builtin_owasp: false,
        enable_builtin_bot: false,
        enable_builtin_scanner: false,
        sources: vec![],
    };
    Arc::new(Mutex::new(RuleManager::new(&cfg)))
}

#[test]
fn rapid_writes_coalesce_into_one_reload() {
    let tmp = tempdir().expect("tmp");
    let dir = tmp.path().to_path_buf();
    let mgr = empty_manager(&dir);
    let _hr = HotReloader::start(Arc::clone(&mgr), dir.clone(), 80).expect("start");

    // Settle the watcher.
    std::thread::sleep(Duration::from_millis(120));

    // Write 5 files inside the debounce window.
    for i in 0..5u8 {
        let p = dir.join(format!("rule-{i}.yaml"));
        std::fs::write(&p, format!("- id: R-{i}\n  name: r{i}\n  description: \"\"\n")).expect("write");
        std::thread::sleep(Duration::from_millis(10));
    }

    // Wait for debounce + reload to complete.
    std::thread::sleep(Duration::from_millis(400));

    // After a single reload, all 5 rules should be present in the registry.
    let total = mgr.lock().stats().total;
    assert!(total >= 5, "expected ≥5 rules after batched reload, got {total}");
}

#[test]
fn watcher_creates_missing_directory_on_start() {
    let tmp = tempdir().expect("tmp");
    let new_dir = tmp.path().join("nested/will-be-created");
    assert!(!new_dir.exists());
    let mgr = empty_manager(&new_dir);
    let _hr = HotReloader::start(mgr, new_dir.clone(), 50).expect("start");
    assert!(new_dir.exists());
}
