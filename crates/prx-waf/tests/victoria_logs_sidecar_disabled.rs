//! Integration tests for the disabled-spawn fast path of
//! `victoria_logs::sidecar::VictoriaLogsSidecar::spawn`. The full happy path
//! cannot be tested without spawning a real `victoria-logs` binary, but the
//! disabled branch is the one operators rely on most often.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use waf_common::config::VictoriaLogsConfig;

#[path = "../src/victoria_logs/sidecar.rs"]
mod sidecar_under_test;

use sidecar_under_test::VictoriaLogsSidecar;

#[tokio::test]
async fn spawn_disabled_returns_none_without_touching_fs() {
    let cfg = VictoriaLogsConfig {
        enabled: false,
        binary_path: "/nonexistent/binary".to_string(),
        storage_data_path: "/nonexistent/storage".to_string(),
        ..VictoriaLogsConfig::default()
    };
    let result = VictoriaLogsSidecar::spawn(&cfg).await.unwrap();
    assert!(result.is_none(), "disabled sidecar must yield None");
}

#[tokio::test]
async fn spawn_enabled_with_missing_binary_fails_fast() {
    let dir = tempfile::tempdir().unwrap();
    let storage = dir.path().join("data");
    let cfg = VictoriaLogsConfig {
        enabled: true,
        binary_path: "/this/binary/does/not/exist/anywhere".to_string(),
        storage_data_path: storage.to_string_lossy().to_string(),
        ..VictoriaLogsConfig::default()
    };
    let result = VictoriaLogsSidecar::spawn(&cfg).await;
    let err = match result {
        Ok(_) => panic!("missing binary must fail"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("spawn") || msg.contains("does not exist") || msg.contains("No such file"),
        "expected spawn-failure message, got: {msg}"
    );
}
