//! Tests for `relay/intel` feed refresh error paths + ASN classifier mop-up.
//!
//! Covers: IptoasnFeed airgap (no URL) → NotModified, IpinfoLiteFeed airgap,
//! IptoasnTsv malformed rows skipped, empty file → no entries,
//! IPv6 entries parsed and looked up, missing mmdb file errors,
//! reload_asn / reload_config / reload_tor public helpers.

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::ArcSwap;
use waf_engine::relay::intel::asn_feed::IpinfoLiteFeed;
use waf_engine::relay::intel::asn_feed_iptoasn::IptoasnFeed;
use waf_engine::relay::intel::http::build_client;
use waf_engine::relay::intel::{AsnDb, IntelProvider, RefreshOutcome};

// ── IpinfoLiteFeed airgap ─────────────────────────────────────────────────────

#[tokio::test]
async fn ipinfo_lite_feed_airgap_returns_not_modified() {
    let feed = IpinfoLiteFeed::new(
        None,
        PathBuf::from("/tmp/nonexistent_ipinfo.mmdb"),
        build_client(None).expect("client"),
    );
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::NotModified));
}

// ── IptoasnFeed airgap ────────────────────────────────────────────────────────

#[tokio::test]
async fn iptoasn_feed_airgap_returns_not_modified() {
    let feed = IptoasnFeed::new(
        None,
        PathBuf::from("/tmp/nonexistent_iptoasn.tsv"),
        build_client(None).expect("client"),
    );
    let out = feed.refresh().await.expect("ok");
    assert!(matches!(out, RefreshOutcome::NotModified));
}

// ── IptoasnTsv parsing ────────────────────────────────────────────────────────

use waf_engine::relay::intel::asn_feed_iptoasn::IptoasnTsv;

fn write_tsv(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(content.as_bytes()).expect("write");
    f
}

#[test]
fn iptoasn_tsv_parses_well_formed_v4_entries() {
    let tsv = "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n\
               1.1.1.0\t1.1.1.255\t13335\tUS\tCLOUDFLARE\n";
    let f = write_tsv(tsv);
    let db = IptoasnTsv::load(f.path()).expect("load");

    let r = db.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).expect("hit");
    assert_eq!(r.asn, 15169);
    assert_eq!(r.org, "GOOGLE");

    let r2 = db.lookup(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))).expect("hit");
    assert_eq!(r2.asn, 13335);
}

#[test]
fn iptoasn_tsv_empty_file_produces_no_entries() {
    let f = write_tsv("");
    let db = IptoasnTsv::load(f.path()).expect("load");
    let ip = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
    assert!(db.lookup(ip).is_none());
    assert_eq!(db.name(), "iptoasn");
}

#[test]
fn iptoasn_tsv_skips_malformed_rows_and_zero_asn() {
    let tsv = "BAD LINE NO TABS\n\
               1.0.0.0\t1.0.0.255\t0\tZZ\tUNROUTED\n\
               missing-cols\n\
               2.0.0.0\t2.0.0.255\t99\tXX\tVALID\n";
    let f = write_tsv(tsv);
    let db = IptoasnTsv::load(f.path()).expect("load");

    // Only the VALID entry at ASN 99 should be present.
    assert!(db.lookup(IpAddr::V4(Ipv4Addr::new(1, 0, 0, 5))).is_none());
    assert_eq!(
        db.lookup(IpAddr::V4(Ipv4Addr::new(2, 0, 0, 5))).map(|r| r.asn),
        Some(99)
    );
}

#[test]
fn iptoasn_tsv_miss_outside_any_range() {
    let tsv = "10.0.0.0\t10.0.0.255\t64512\tXX\tPRIVATE\n";
    let f = write_tsv(tsv);
    let db = IptoasnTsv::load(f.path()).expect("load");

    assert!(db.lookup(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1))).is_none());
    assert!(db.lookup(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))).is_none());
}

#[test]
fn iptoasn_tsv_ipv6_entries_parsed_and_found() {
    let tsv = "2001:db8::\t2001:db8::ffff\t64496\tXX\tDOCRFC\n";
    let f = write_tsv(tsv);
    let db = IptoasnTsv::load(f.path()).expect("load");

    let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001));
    let r = db.lookup(ip).expect("hit");
    assert_eq!(r.asn, 64496);
    assert_eq!(r.org, "DOCRFC");
}

#[test]
fn iptoasn_tsv_missing_file_returns_error() {
    let res = IptoasnTsv::load(&PathBuf::from("/nonexistent/path.tsv"));
    assert!(res.is_err());
}

// ── IpinfoLiteMmdb open errors ────────────────────────────────────────────────

use waf_engine::relay::intel::asn_feed::IpinfoLiteMmdb;

#[test]
fn ipinfo_lite_mmdb_missing_file_errors() {
    let res = IpinfoLiteMmdb::open(&PathBuf::from("/nonexistent/asn.mmdb"));
    assert!(res.is_err());
}

// ── reload_asn / reload_tor helpers ──────────────────────────────────────────

use waf_engine::relay::intel::EmptyAsnDb;
use waf_engine::relay::providers::TorSet;
use waf_engine::relay::providers::asn_classifier::SwapAsnDb;
use waf_engine::relay::reload::{AsnFormat, reload_asn, reload_tor};

#[test]
fn reload_asn_from_valid_tsv_swaps_db() {
    let tsv = "8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n";
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(tsv.as_bytes()).expect("write");

    let store: SwapAsnDb = ArcSwap::from_pointee(Box::new(EmptyAsnDb) as Box<dyn AsnDb>);
    reload_asn(f.path(), &store, AsnFormat::IptoasnTsv);

    // After reload the db should find the entry.
    let loaded = store.load();
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(loaded.lookup(ip).is_some());
}

#[test]
fn reload_asn_from_missing_file_keeps_previous() {
    let store: SwapAsnDb = ArcSwap::from_pointee(Box::new(EmptyAsnDb) as Box<dyn AsnDb>);
    let ptr_before = Arc::as_ptr(&store.load_full());

    reload_asn(&PathBuf::from("/nonexistent/asn.tsv"), &store, AsnFormat::IptoasnTsv);

    let ptr_after = Arc::as_ptr(&store.load_full());
    assert_eq!(ptr_before, ptr_after, "snapshot should be retained on load failure");
}

#[test]
fn reload_tor_from_valid_file_swaps_set() {
    let mut f = tempfile::NamedTempFile::new().expect("tmp");
    f.write_all(b"203.0.113.7\n198.51.100.1\n").expect("write");

    let store = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    reload_tor(f.path(), &store);

    assert_eq!(store.load().len(), 2);
}

#[test]
fn reload_tor_from_missing_file_keeps_previous() {
    let store = Arc::new(ArcSwap::from(Arc::new(TorSet::default())));
    let ptr_before = Arc::as_ptr(&store.load_full());

    reload_tor(&PathBuf::from("/nonexistent/tor.txt"), &store);

    let ptr_after = Arc::as_ptr(&store.load_full());
    assert_eq!(ptr_before, ptr_after);
}

// ── EmptyAsnDb always returns None ────────────────────────────────────────────

#[test]
fn empty_asn_db_always_misses() {
    let db = EmptyAsnDb;
    assert!(db.lookup(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))).is_none());
    assert!(db.lookup(IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());
    assert_eq!(db.name(), "empty");
}
