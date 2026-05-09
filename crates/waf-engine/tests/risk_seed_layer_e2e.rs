//! FR-025 — L0 seed layer file-driven loader integration coverage.

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

use std::fs;
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tempfile::tempdir;
use waf_engine::risk::seed::reload::load_tables;
use waf_engine::risk::seed::{SeedDeltas, SeedLayer, SeedPaths, SeedReloader, SeedTablesBuilder, SeedVerdict};
use waf_engine::risk::state::SeedKind;

#[test]
fn load_from_paths_constructs_layer_with_all_files() {
    let dir = tempdir().unwrap();
    let tor = dir.path().join("tor.txt");
    let asn = dir.path().join("asn.csv");
    let wl = dir.path().join("wl.txt");

    fs::write(&tor, "9.9.9.9\n").unwrap();
    // ASN CSV: cidr,asn,classification (datacenter)
    fs::write(&asn, "52.0.0.0/8,16509,datacenter\n").unwrap();
    fs::write(&wl, "10.0.0.0/8\n").unwrap();

    let layer = SeedLayer::load_from_paths(Some(&tor), Some(&asn), Some(&wl), SeedDeltas::default());

    assert_eq!(
        layer.evaluate(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))),
        SeedVerdict::Score {
            delta: 30,
            kind: SeedKind::TorExit,
        }
    );
    assert_eq!(
        layer.evaluate(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
        SeedVerdict::Whitelisted,
    );
    let dc_verdict = layer.evaluate(IpAddr::V4(Ipv4Addr::new(52, 95, 0, 1)));
    assert!(
        matches!(
            dc_verdict,
            SeedVerdict::Score {
                kind: SeedKind::DatacenterASN,
                ..
            }
        ),
        "expected datacenter, got {dc_verdict:?}",
    );
}

#[test]
fn load_from_paths_handles_all_none() {
    let layer = SeedLayer::load_from_paths(None, None, None, SeedDeltas::default());
    assert_eq!(layer.evaluate(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), SeedVerdict::None,);
}

#[test]
fn load_tables_with_all_paths() {
    let dir = tempdir().unwrap();
    let tor = dir.path().join("tor.txt");
    let asn = dir.path().join("asn.csv");
    let wl = dir.path().join("wl.txt");

    fs::write(&tor, "1.1.1.1\n").unwrap();
    fs::write(&asn, "8.8.0.0/16,15169,datacenter\n").unwrap();
    fs::write(&wl, "192.168.0.0/16\n").unwrap();

    let paths = SeedPaths {
        tor_exits: Some(tor),
        asn_classes: Some(asn),
        whitelist: Some(wl),
    };
    let tables = load_tables(&paths);
    assert!(tables.is_tor_exit(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    assert!(tables.is_whitelisted(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    assert!(tables.lookup_asn(IpAddr::V4(Ipv4Addr::new(8, 8, 0, 1))).is_some());
}

#[test]
fn seed_reloader_starts_with_no_paths_disabled() {
    let paths = SeedPaths {
        tor_exits: None,
        asn_classes: None,
        whitelist: None,
    };
    let swap = Arc::new(ArcSwap::from(SeedTablesBuilder::new().build().into_arc()));
    // No paths → reloader returns Ok with empty watcher set.
    let _reloader = SeedReloader::start(paths, swap, 50).expect("start with no paths");
}

#[test]
fn seed_reloader_observes_whitelist_change() {
    let dir = tempdir().unwrap();
    let wl = dir.path().join("wl.txt");
    fs::write(&wl, "").unwrap();

    let paths = SeedPaths {
        tor_exits: None,
        asn_classes: None,
        whitelist: Some(wl.clone()),
    };

    let initial = load_tables(&paths);
    let swap = Arc::new(ArcSwap::from(Arc::new(initial)));
    let _reloader = SeedReloader::start(paths, Arc::clone(&swap), 100).unwrap();

    // Now write a whitelist entry; reloader should pick it up.
    let mut f = fs::File::create(&wl).unwrap();
    writeln!(f, "10.0.0.0/8").unwrap();
    f.sync_all().unwrap();
    drop(f);

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if swap.load().is_whitelisted(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("hot reload never observed whitelist entry");
}

#[test]
fn seed_layer_swap_tables_replaces_data() {
    let layer = SeedLayer::empty();
    let ip = IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2));
    assert_eq!(layer.evaluate(ip), SeedVerdict::None);

    let mut b = SeedTablesBuilder::new();
    b.add_tor_exit(ip);
    layer.swap_tables(b.build().into_arc());
    assert!(matches!(layer.evaluate(ip), SeedVerdict::Score { .. }));

    // Access tables_swap publicly for observability.
    let arc_ref = layer.tables_swap();
    assert!(arc_ref.load().is_tor_exit(ip));
}
