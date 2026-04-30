//! FR-008 AC-08 — Reload-under-load stress test.
//!
//! 16 reader threads each run a tight `evaluate()` loop for 2 seconds while a
//! writer thread rewrites the YAML mid-flight. After all threads join we assert:
//!   - No panic occurred (join handles are unwrapped).
//!   - The ArcSwap snapshot reflects the new state within a 2-second poll window.
//!
//! This exercises the lock-free `ArcSwap` swap path under genuine read pressure
//! and validates AC-08 ("no panic under concurrent reload").
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::redundant_clone,
    clippy::manual_assert,
    clippy::uninlined_format_args
)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tempfile::TempDir;
use waf_common::tier::Tier;
use waf_engine::access::{AccessLists, AccessReloader, AccessRequestView, DEFAULT_DEBOUNCE_MS};

// ── YAML fixtures ─────────────────────────────────────────────────────────────

/// Initial YAML: empty blacklist.
const V1_YAML: &str = r"
version: 1
dry_run: false
ip_whitelist: []
ip_blacklist: []
";

/// Rewritten YAML: 8 blacklist entries. Readers should see this after the swap.
const V2_YAML: &str = r"
version: 1
dry_run: false
ip_whitelist: []
ip_blacklist:
  - 203.0.113.1
  - 203.0.113.2
  - 203.0.113.3
  - 203.0.113.4
  - 203.0.113.5
  - 203.0.113.6
  - 203.0.113.7
  - 203.0.113.8
";

/// Number of expected blacklist entries in V2. Used in poll assertion.
const V2_BLACKLIST_LEN: usize = 8;

/// Number of concurrent reader threads.
const READER_THREADS: usize = 16;

/// How long each reader thread runs its evaluate() loop.
const READER_DURATION: Duration = Duration::from_secs(2);

/// Poll interval when waiting for the swap to become visible.
const POLL_TICK: Duration = Duration::from_millis(50);

/// Maximum time to wait for V2 to appear in the snapshot after the writer finishes.
const SWAP_TIMEOUT: Duration = Duration::from_secs(2);

// ── helpers ───────────────────────────────────────────────────────────────────

fn make_view(ip: IpAddr, host: &str, tier: Tier) -> AccessRequestView<'_> {
    AccessRequestView {
        client_ip: ip,
        host,
        tier,
    }
}

fn write_and_spawn(dir: &TempDir, initial_yaml: &str) -> (std::path::PathBuf, Arc<ArcSwap<AccessLists>>) {
    let path = dir.path().join("access-lists.yaml");
    std::fs::write(&path, initial_yaml).expect("write initial yaml");
    let path = path.canonicalize().expect("canonicalize path");
    let lists = AccessLists::from_yaml_path(&path).expect("initial parse");
    let store = Arc::new(ArcSwap::new(lists));
    (path, store)
}

// ── test ──────────────────────────────────────────────────────────────────────

/// AC-08: 16 reader threads × 2 s, mid-flight YAML rewrite, no panic,
/// post-swap snapshot reflects V2 within 2 s.
#[test]
fn reload_under_concurrent_reads_no_panic() {
    let dir = TempDir::new().expect("tempdir");
    let (path, store) = write_and_spawn(&dir, V1_YAML);

    let _reloader =
        AccessReloader::spawn(path.clone(), Arc::clone(&store), DEFAULT_DEBOUNCE_MS).expect("spawn reloader");

    // Give watcher a moment to fully attach.
    std::thread::sleep(Duration::from_millis(300));

    // Precondition.
    assert_eq!(store.load().config().ip_blacklist.len(), 0, "precondition: v1 empty");

    // ── spawn 16 reader threads ───────────────────────────────────────────────
    let mut handles = Vec::with_capacity(READER_THREADS);
    for i in 0..READER_THREADS {
        let store_clone = Arc::clone(&store);
        // Each thread uses a distinct IP so there is no shared L1-cache line bias.
        let client_ip: IpAddr = format!("10.0.{}.{}", i / 256, i % 256).parse().expect("valid ip");
        let handle = std::thread::spawn(move || {
            let end = Instant::now() + READER_DURATION;
            let view = make_view(client_ip, "bench.example.com", Tier::Medium);
            while Instant::now() < end {
                let snap = store_clone.load();
                // evaluate() must never panic regardless of mid-flight swap.
                let _ = snap.evaluate(&view);
            }
        });
        handles.push(handle);
    }

    // ── writer: sleep 300ms then rewrite mid-flight ───────────────────────────
    let writer_path = path.clone();
    let writer = std::thread::spawn(move || {
        // Readers have been running for ~300ms at this point.
        std::thread::sleep(Duration::from_millis(300));
        std::fs::write(&writer_path, V2_YAML).expect("write v2");
    });

    // Join writer — must not panic.
    writer.join().expect("writer panicked");

    // Join all readers — any panic propagates here.
    for (i, h) in handles.into_iter().enumerate() {
        h.join().unwrap_or_else(|e| panic!("reader thread {i} panicked: {e:?}"));
    }

    // ── poll until the swap is visible (max 2 s) ─────────────────────────────
    let deadline = Instant::now() + SWAP_TIMEOUT;
    loop {
        let len = store.load().config().ip_blacklist.len();
        if len == V2_BLACKLIST_LEN {
            break;
        }
        if Instant::now() >= deadline {
            panic!(
                "snapshot did not reflect V2 within {:?}; blacklist.len()={len} (expected {V2_BLACKLIST_LEN})",
                SWAP_TIMEOUT
            );
        }
        std::thread::sleep(POLL_TICK);
    }
}
