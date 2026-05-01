//! FR-008 phase-07 — AC-08: hot-reload swap under concurrent read load.
//!
//! Drives many reader threads against `ArcSwap<AccessLists>` while a writer
//! rewrites the YAML mid-flight. Asserts:
//!   - zero reader panics / parse errors,
//!   - post-swap readers eventually observe the new blacklist (within 2 s),
//!   - the original snapshot keeps serving consistent answers prior to swap.
//!
//! No `sleep`-based timing assertions: we poll `ArcSwap.load()` for the new
//! state with a 2-second timeout and 50 ms tick (per phase-07 plan pitfall).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use waf_common::tier::Tier;
use waf_engine::access::{AccessLists, AccessReloader, AccessRequestView};

const V1: &str = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n";
const V2: &str = "version: 1\nip_blacklist:\n  - 203.0.113.0/24\n  - 198.51.100.42/32\n";

const READERS: usize = 16;
const READER_DURATION: Duration = Duration::from_secs(2);
const POLL_TIMEOUT: Duration = Duration::from_secs(2);
const POLL_TICK: Duration = Duration::from_millis(50);
const DEBOUNCE_MS: u64 = 50;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("test ip parses")
}

#[test]
fn t_reload_under_load_no_drops() {
    let tmp = tempfile::tempdir().expect("tmpdir");
    let path = tmp.path().join("access-lists.yaml");
    std::fs::write(&path, V1).expect("write v1");

    let initial = AccessLists::from_yaml_path(&path).expect("v1 parse");
    let store: Arc<ArcSwap<AccessLists>> = Arc::new(ArcSwap::from(initial));

    let _reloader = AccessReloader::spawn(path.clone(), Arc::clone(&store), DEBOUNCE_MS).expect("spawn");

    // Spin up readers. Each thread loops on `evaluate()` and counts reads. A
    // panic in any reader will be surfaced via the join handle below.
    let stop = Arc::new(AtomicBool::new(false));
    let total_reads = Arc::new(AtomicUsize::new(0));
    let v1_only_ip = ip("203.0.113.5"); // matches both v1 and v2 (always blocked)
    let v2_only_ip = ip("198.51.100.42"); // only blocked after swap

    let mut handles = Vec::with_capacity(READERS);
    for _ in 0..READERS {
        let store = Arc::clone(&store);
        let stop = Arc::clone(&stop);
        let counter = Arc::clone(&total_reads);
        handles.push(std::thread::spawn(move || {
            let view_a = AccessRequestView {
                client_ip: v1_only_ip,
                host: "h",
                tier: Tier::Medium,
            };
            let view_b = AccessRequestView {
                client_ip: v2_only_ip,
                host: "h",
                tier: Tier::Medium,
            };
            while !stop.load(Ordering::Relaxed) {
                let snap = store.load_full();
                // Always-blocked IP must always be blocked — invariant across snapshots.
                let d_a = snap.evaluate(&view_a);
                assert!(
                    matches!(d_a, waf_engine::access::AccessDecision::Block { .. }),
                    "v1-range IP must always be blocked across reloads"
                );
                // Other IP — outcome depends on snapshot, both `Continue` and
                // `Block` are valid; we only assert it doesn't panic / yield
                // garbage.
                let _ = snap.evaluate(&view_b);
                counter.fetch_add(2, Ordering::Relaxed);
            }
        }));
    }

    // Mid-load: write V2.
    std::thread::sleep(Duration::from_millis(150)); // let readers warm up
    std::fs::write(&path, V2).expect("write v2");

    // Poll for swap visibility instead of sleeping a fixed duration.
    let saw_swap = poll_until(POLL_TIMEOUT, POLL_TICK, || {
        store.load().config().ip_blacklist.len() == 2
    });
    assert!(saw_swap, "v2 snapshot must be visible within {POLL_TIMEOUT:?}");

    // Post-swap: confirm readers see the new blacklist.
    let view_b = AccessRequestView {
        client_ip: ip("198.51.100.42"),
        host: "h",
        tier: Tier::Medium,
    };
    let saw_v2_block = poll_until(POLL_TIMEOUT, POLL_TICK, || {
        matches!(
            store.load().evaluate(&view_b),
            waf_engine::access::AccessDecision::Block { .. }
        )
    });
    assert!(saw_v2_block, "post-swap reader must see v2 blacklist entry");

    // Let load run a touch longer post-swap, then stop.
    let elapsed_budget = READER_DURATION.saturating_sub(Instant::now().elapsed());
    std::thread::sleep(elapsed_budget.min(Duration::from_millis(500)));
    stop.store(true, Ordering::Relaxed);

    for h in handles {
        h.join().expect("reader thread did not panic");
    }
    assert!(
        total_reads.load(Ordering::Relaxed) > 0,
        "readers should have made progress"
    );
}

fn poll_until(timeout: Duration, tick: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if cond() {
            return true;
        }
        std::thread::sleep(tick);
    }
    cond()
}
