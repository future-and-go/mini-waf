//! FR-008 — Hot-reload integration tests for the access-lists watcher.
//!
//! Two cases:
//!   1. Valid YAML v2 written mid-flight → snapshot swapped within debounce window.
//!   2. Bad YAML written mid-flight → prior snapshot retained.
//!
//! These tests use `tokio::time::sleep` to wait out the debounce + settle window
//! (debounce=100ms, sleep=800ms gives >3× headroom on slow CI).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use tempfile::TempDir;
use waf_engine::access::{AccessLists, AccessReloader};

/// Debounce fed to the watcher in these tests. Use a shorter window than the
/// default (250ms) so tests are fast, but still generous relative to CI.
const DEBOUNCE_MS: u64 = 100;

/// How long to wait after writing a file before asserting the swap occurred.
/// 800ms >> debounce (100ms) + watcher settle (~50ms) — safe even on slow CI.
const SETTLE: Duration = Duration::from_millis(800);

// ── YAML fixtures ────────────────────────────────────────────────────────────

/// Initial state: empty blacklist.
const V1_YAML: &str = r"
version: 1
dry_run: false
ip_whitelist: []
ip_blacklist: []
";

/// Updated state: one blacklist entry. Used to assert the swap happened.
const V2_YAML: &str = r"
version: 1
dry_run: false
ip_whitelist: []
ip_blacklist:
  - 203.0.113.42
";

/// Invalid YAML — parser rejects this, keeping prior snapshot.
const BAD_YAML: &str = "version: 1\nip_blacklist:\n  - not-an-ip\n";

// ── helpers ───────────────────────────────────────────────────────────────────

fn write_and_spawn(dir: &TempDir, initial_yaml: &str) -> (std::path::PathBuf, Arc<ArcSwap<AccessLists>>) {
    let path = dir.path().join("access-lists.yaml");
    // Canonicalize so FSEvents on macOS matches the watch path.
    let path = {
        std::fs::write(&path, initial_yaml).expect("write initial yaml");
        path.canonicalize().expect("canonicalize path")
    };
    let lists = AccessLists::from_yaml_path(&path).expect("initial parse");
    let store = Arc::new(ArcSwap::new(lists));
    (path, store)
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// Happy path: write V1 → spawn watcher → write V2 → wait → assert swap visible.
#[tokio::test]
async fn reload_replaces_snapshot_on_valid_yaml() {
    let dir = TempDir::new().expect("tempdir");
    let (path, store) = write_and_spawn(&dir, V1_YAML);

    // Spawn watcher — drop handle at end of test to stop it.
    let _reloader = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn reloader");

    // Let the OS watcher fully attach before mutating.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Precondition: snapshot has empty blacklist.
    assert_eq!(
        store.load().config().ip_blacklist.len(),
        0,
        "precondition: v1 empty blacklist"
    );

    // Write v2 — has one blacklist entry.
    std::fs::write(&path, V2_YAML).expect("write v2");

    // Wait for debounce + settle.
    tokio::time::sleep(SETTLE).await;

    let snap = store.load();
    assert_eq!(
        snap.config().ip_blacklist.len(),
        1,
        "expected v2 blacklist (1 entry) after hot-reload"
    );
}

/// Error path: write V1 → spawn watcher → write bad YAML → wait → prior snapshot retained.
#[tokio::test]
async fn reload_keeps_prior_on_bad_yaml() {
    let dir = TempDir::new().expect("tempdir");
    let (path, store) = write_and_spawn(&dir, V1_YAML);

    let _reloader = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn reloader");

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Record the pointer of the current snapshot for identity comparison.
    let prior_ptr = Arc::as_ptr(&store.load_full());

    // Write bad YAML.
    std::fs::write(&path, BAD_YAML).expect("write bad yaml");
    tokio::time::sleep(SETTLE).await;

    let now_ptr = Arc::as_ptr(&store.load_full());
    assert_eq!(
        prior_ptr, now_ptr,
        "snapshot pointer must be unchanged after bad-YAML reload"
    );
}
