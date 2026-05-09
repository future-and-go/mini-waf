//! Phase 07 — `RuleManager::load_all` dispatches by file format and isolates
//! per-file errors.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;

use tempfile::tempdir;
use waf_common::config::RulesConfig;
use waf_engine::rules::manager::RuleManager;

fn make_config(dir: &std::path::Path) -> RulesConfig {
    RulesConfig {
        dir: dir.display().to_string(),
        hot_reload: false,
        reload_debounce_ms: 0,
        enable_builtin_owasp: false,
        enable_builtin_bot: false,
        enable_builtin_scanner: false,
        sources: vec![],
    }
}

#[test]
fn loads_yaml_and_skips_unknown_extensions() {
    let tmp = tempdir().expect("tmp");
    let dir = tmp.path();
    fs::write(dir.join("ok.yaml"), "- id: TEST-OK\n  name: ok\n  description: \"\"\n").expect("write ok");
    fs::write(dir.join("readme.txt"), "plain text — no parser registered").expect("write txt");
    let mut mgr = RuleManager::new(&make_config(dir));
    let report = mgr.load_all().expect("load");
    // 1 yaml file loaded; .txt skipped.
    assert!(report.rules_loaded >= 1);
    assert!(mgr.search("ok").iter().any(|r| r.id == "TEST-OK"));
}

#[test]
fn invalid_yaml_is_isolated_does_not_block_other_files() {
    let tmp = tempdir().expect("tmp");
    let dir = tmp.path();
    fs::write(
        dir.join("good.yaml"),
        "- id: GOOD-1\n  name: good\n  description: \"\"\n",
    )
    .expect("write good");
    fs::write(dir.join("broken.yaml"), "not: [valid yaml\n  at all").expect("write broken");
    let mut mgr = RuleManager::new(&make_config(dir));
    let report = mgr.load_all().expect("load_all (must not propagate parse errors)");
    assert!(!report.errors.is_empty(), "broken file must register an error");
    assert!(mgr.search("good").iter().any(|r| r.id == "GOOD-1"));
}

#[test]
fn reload_clears_then_repopulates_registry() {
    let tmp = tempdir().expect("tmp");
    let dir = tmp.path();
    fs::write(dir.join("a.yaml"), "- id: A-1\n  name: a\n  description: \"\"\n").expect("write a");
    let mut mgr = RuleManager::new(&make_config(dir));
    mgr.load_all().expect("first load");
    let before = mgr.stats().total;
    assert!(before >= 1);

    // Add another file, reload, both rules should now be present (and report.added == 1).
    fs::write(dir.join("b.yaml"), "- id: B-1\n  name: b\n  description: \"\"\n").expect("write b");
    let report = mgr.reload().expect("reload");
    assert!(report.added >= 1, "second reload must report at least 1 added");
}

#[test]
fn validate_file_rejects_unknown_extension() {
    let tmp = tempdir().expect("tmp");
    let bad = tmp.path().join("rule.unknown");
    fs::write(&bad, "ignored").expect("write");
    let mgr = RuleManager::new(&make_config(tmp.path()));
    assert!(mgr.validate_file(&bad).is_err());
}

#[test]
fn import_from_file_returns_count() {
    let tmp = tempdir().expect("tmp");
    let p = tmp.path().join("imp.yaml");
    fs::write(&p, "- id: IMP-1\n  name: imp\n  description: \"\"\n").expect("write");
    let mut mgr = RuleManager::new(&make_config(tmp.path()));
    let n = mgr.import_from_file(&p).expect("import");
    assert!(n >= 1);
}
