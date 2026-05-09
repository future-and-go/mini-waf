//! Phase 05: cache bootstrap with memory backend.

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

use std::path::PathBuf;

use gateway::cache::init_response_cache;
use waf_common::config::CacheConfig;

#[tokio::test]
async fn init_with_default_memory_backend_succeeds() {
    let cfg = CacheConfig::default();
    let init = init_response_cache(&cfg).await.expect("init");
    // Memory backend has no embedded supervisor and no rules watcher.
    assert!(init.embedded_supervisor.is_none());
    assert!(init.rules_watcher.is_none());
    // Cache is constructed with a backend; entry count starts at 0.
    assert_eq!(init.cache.entry_count(), 0);
}

#[tokio::test]
async fn init_with_missing_rules_path_errors() {
    let mut cfg = CacheConfig::default();
    cfg.rules_path = Some(PathBuf::from("/definitely/not/a/real/path/cache.yaml"));
    let res = init_response_cache(&cfg).await;
    assert!(res.is_err(), "missing rules file should fail to load");
}

#[tokio::test]
async fn init_with_empty_rules_yaml_succeeds_with_watcher() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p = dir.path().join("cache.yaml");
    // Minimal valid empty rule list.
    std::fs::write(&p, "version: 1\nrules: []\n").expect("write");
    let mut cfg = CacheConfig::default();
    cfg.rules_path = Some(p);
    let init = init_response_cache(&cfg).await.expect("init with empty rules");
    assert!(init.rules_watcher.is_some(), "watcher should be spawned");
    drop(init); // shut down watcher cleanly
}

#[tokio::test]
async fn init_with_low_max_size_still_constructs() {
    let mut cfg = CacheConfig::default();
    cfg.max_size_mb = 1;
    cfg.default_ttl_secs = 5;
    cfg.max_ttl_secs = 30;
    let init = init_response_cache(&cfg).await.expect("init");
    assert_eq!(init.cache.entry_count(), 0);
}
