//! Extra coverage for `access::reload` — create / remove event kinds and
//! the SIGHUP listener path. Mirrors `access_hot_reload.rs` patterns.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use waf_engine::access::reload::reload;
use waf_engine::access::{AccessLists, AccessReloader};

const V1: &str = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n";
const V2: &str = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n  - 198.51.100.42\n";

const DEBOUNCE_MS: u64 = 80;
const SETTLE: Duration = Duration::from_millis(700);

#[test]
fn t_reload_observes_file_creation() {
    // Create-after-spawn should trigger reload (Create event branch).
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");

    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(AccessLists::empty()));
    let _r = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn");

    std::fs::write(&path, V1).expect("write v1");
    std::thread::sleep(SETTLE);

    assert_eq!(
        store.load().config().ip_blacklist.len(),
        1,
        "create event must trigger reload"
    );
}

#[test]
fn t_reload_remove_then_recreate() {
    // Remove + recreate should also exercise the Remove branch then Create.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");
    std::fs::write(&path, V1).expect("seed v1");

    let initial = AccessLists::from_yaml_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(initial));
    let _r = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn");

    std::fs::remove_file(&path).expect("remove");
    std::thread::sleep(SETTLE);
    // Reload after removal hits the AccessLists::from_yaml_path error path
    // so previous snapshot is retained — count stays at 1.
    assert_eq!(store.load().config().ip_blacklist.len(), 1);

    std::fs::write(&path, V2).expect("write v2");
    std::thread::sleep(SETTLE);
    assert_eq!(store.load().config().ip_blacklist.len(), 2);
}

#[test]
fn t_reload_function_directly_swaps() {
    // Directly invoke the public `reload` helper.
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");
    std::fs::write(&path, V1).expect("seed v1");

    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(AccessLists::empty()));
    assert_eq!(store.load().config().ip_blacklist.len(), 0);

    reload(&path, &store);
    assert_eq!(store.load().config().ip_blacklist.len(), 1);
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t_sighup_listener_can_be_spawned() {
    use waf_engine::access::reload::spawn_sighup_listener;

    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");
    std::fs::write(&path, V1).expect("seed v1");

    let initial = AccessLists::from_yaml_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(initial));

    // Verify the listener spawns without error inside a tokio runtime.
    // We don't fire an actual SIGHUP because raising it process-wide would
    // race with the test harness's own signal handlers.
    let handle = spawn_sighup_listener(path.clone(), Arc::clone(&store)).expect("spawn sighup");
    handle.abort();
    let _ = handle.await;
}
