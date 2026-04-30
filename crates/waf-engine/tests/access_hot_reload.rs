//! FR-008 phase-06 — Access-list hot-reload integration tests.
//!
//! Drives the watcher end-to-end through the filesystem (no test seam) so the
//! debounce + parent-dir watch logic is exercised in realistic conditions.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use waf_common::tier::Tier;
use waf_engine::access::{AccessLists, AccessReloader};

const V1: &str = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n";
const V2: &str = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n  - 198.51.100.42\n";
const BAD: &str = "version: 1\nip_blacklist:\n  - not-a-cidr\n";

/// Short debounce keeps the test fast while still exercising the timer path.
const DEBOUNCE_MS: u64 = 100;
/// Generous slack — CI filesystems can coalesce events slowly.
const SETTLE: Duration = Duration::from_millis(800);

#[test]
fn t_reload_swap() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");
    std::fs::write(&path, V1).expect("write v1");

    let initial = AccessLists::from_yaml_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(initial));
    assert_eq!(store.load().config().ip_blacklist.len(), 1, "v1 baseline");

    let _r = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn");

    std::fs::write(&path, V2).expect("write v2");
    std::thread::sleep(SETTLE);

    assert_eq!(
        store.load().config().ip_blacklist.len(),
        2,
        "v2 should be live after reload"
    );
}

#[test]
fn t_reload_bad_yaml_keeps_prior() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");
    std::fs::write(&path, V1).expect("write v1");

    let initial = AccessLists::from_yaml_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(initial));
    let prior_ptr = Arc::as_ptr(&store.load_full());

    let _r = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn");

    std::fs::write(&path, BAD).expect("write bad");
    std::thread::sleep(SETTLE);

    let now_ptr = Arc::as_ptr(&store.load_full());
    assert_eq!(prior_ptr, now_ptr, "snapshot must be unchanged after bad reload");
    assert_eq!(store.load().config().ip_blacklist.len(), 1, "v1 retained");
    let _ = store.load().tier_mode(Tier::Critical);
}
