//! Integration tests for `victoria_logs::installer::ensure_binary` paths
//! that do not require any network or process interaction.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use waf_common::config::VictoriaLogsConfig;

// `installer` is reachable as `prx_waf::victoria_logs::installer` only if the
// crate exposes a lib target. It does not. Instead we re-declare the public
// surface we want to exercise by depending on the binary's `victoria_logs`
// module via the test re-export pattern: include the source file directly.
#[path = "../src/victoria_logs/installer.rs"]
mod installer_under_test;

use installer_under_test::ensure_binary;

fn cfg_with_path(path: PathBuf, enabled: bool, auto_install: bool) -> VictoriaLogsConfig {
    VictoriaLogsConfig {
        enabled,
        binary_path: path.to_string_lossy().to_string(),
        auto_install,
        ..VictoriaLogsConfig::default()
    }
}

#[tokio::test]
async fn ensure_binary_disabled_returns_ok_without_touching_fs() {
    let cfg = cfg_with_path(PathBuf::from("/nonexistent/never/used"), false, true);
    ensure_binary(&cfg).await.expect("disabled config must succeed");
}

#[tokio::test]
async fn ensure_binary_existing_file_skips_install() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("victoria-logs");
    tokio::fs::write(&path, b"already here").await.unwrap();
    let cfg = cfg_with_path(path, true, true);
    ensure_binary(&cfg).await.expect("present binary must short-circuit");
}

#[tokio::test]
async fn ensure_binary_missing_with_auto_install_false_bails() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("never-installed");
    let cfg = cfg_with_path(path, true, false);
    let err = ensure_binary(&cfg).await.expect_err("must error");
    let msg = format!("{err}");
    assert!(
        msg.contains("auto_install = false"),
        "expected auto_install message, got: {msg}"
    );
}
