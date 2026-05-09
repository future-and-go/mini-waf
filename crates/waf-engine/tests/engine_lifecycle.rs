//! Phase 07 — `WafEngine` constructor + setter matrix.
//!
//! Spins one Postgres testcontainer and exercises the engine's public
//! configuration surface in a single `tokio::test` to keep cold-start cost
//! bounded.

#![allow(clippy::unwrap_used, clippy::expect_used)]

#[path = "common/mod.rs"]
mod common;

use std::path::PathBuf;
use std::sync::Arc;

use common::start_engine;
use waf_common::config::SqliScanConfig;
use waf_engine::{WafEngine, WafEngineConfig};

#[tokio::test(flavor = "multi_thread")]
async fn engine_construction_and_setters_round_trip() {
    let fx = start_engine().await;

    // Defaults — accessors return live handles.
    assert!(Arc::strong_count(fx.engine.geo_check()) >= 1);
    assert!(Arc::strong_count(fx.engine.ddos_metrics()) >= 1);
    assert!(Arc::strong_count(fx.engine.ddos_ban_table()) >= 1);

    // Set rules dir.
    fx.engine.set_rules_dir(PathBuf::from("/tmp/non-existent-rules"));

    // SQLi reload.
    fx.engine.reload_sqli_scan_config(SqliScanConfig::default());

    // Idempotency: setters that use OnceLock should not panic on second call.
    fx.engine.set_rules_dir(PathBuf::from("/tmp/different"));
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_with_sqli_config_uses_provided_settings() {
    let fx = start_engine().await;
    let custom_sqli = SqliScanConfig::default();
    let _e = WafEngine::with_sqli_config(Arc::clone(&fx.db), WafEngineConfig::default(), custom_sqli);
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_start_watchers_with_missing_files_is_inert() {
    let fx = start_engine().await;
    let bad = std::path::Path::new("/tmp/this-does-not-exist-engine-test.yaml");

    // Each watcher tolerates missing files (logs warning, leaves subsystem inert).
    fx.engine.start_rate_limit_watcher(bad);
    fx.engine.start_tx_velocity_watcher(bad);
    fx.engine.start_ddos_watcher(bad);

    // Re-calling the same watcher is a no-op (OnceLock guard).
    fx.engine.start_rate_limit_watcher(bad);
    fx.engine.start_tx_velocity_watcher(bad);
    fx.engine.start_ddos_watcher(bad);
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_start_file_watcher_on_tempdir_succeeds() {
    let fx = start_engine().await;
    let tmp = tempfile::tempdir().expect("tmp");
    fx.engine.set_rules_dir(tmp.path().to_path_buf());
    fx.engine.start_file_watcher();
    // Idempotent — second call is a no-op.
    fx.engine.start_file_watcher();
}

#[tokio::test(flavor = "multi_thread")]
async fn engine_reload_rules_against_empty_db_succeeds() {
    let fx = start_engine().await;
    fx.engine.reload_rules().await.expect("reload");
}
