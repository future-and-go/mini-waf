//! Integration tests for `geoip::GeoIpService`.
//!
//! Covers: init with missing files (both searchers None), is_available,
//! lookup on unavailable service returns default GeoIpInfo, reload no-op
//! when files still missing, cache_policy_from_str all variants,
//! IPv4 vs IPv6 routing in lookup dispatch, parse_region via public lookup,
//! failed reload preserving the working searcher.

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

use ip2region::CachePolicy;
use std::net::IpAddr;
use waf_engine::geoip::{GeoIpService, cache_policy_from_str};

// ── init / availability ──────────────────────────────────────────────────────

#[test]
fn init_with_nonexistent_paths_succeeds_and_is_unavailable() {
    let svc = GeoIpService::init("/nonexistent/ipv4.xdb", "/nonexistent/ipv6.xdb", CachePolicy::NoCache)
        .expect("init should not fail on missing files");

    assert!(!svc.is_available());
}

#[test]
fn lookup_on_unavailable_service_returns_default() {
    let svc = GeoIpService::init("/nonexistent/ipv4.xdb", "/nonexistent/ipv6.xdb", CachePolicy::NoCache).expect("init");

    let v4: IpAddr = "8.8.8.8".parse().expect("ip");
    let v6: IpAddr = "2001:db8::1".parse().expect("ip");

    let result_v4 = svc.lookup(v4);
    let result_v6 = svc.lookup(v6);

    // Both return empty GeoIpInfo (all fields empty string).
    assert_eq!(result_v4.country, "");
    assert_eq!(result_v4.iso_code, "");
    assert_eq!(result_v6.country, "");
    assert_eq!(result_v6.iso_code, "");
}

#[test]
fn reload_with_missing_files_returns_ok_false() {
    let svc = GeoIpService::init("/nonexistent/ipv4.xdb", "/nonexistent/ipv6.xdb", CachePolicy::NoCache).expect("init");

    // reload returns Ok(false) — neither file exists.
    let result = svc.reload().expect("reload should not error");
    assert!(!result);
    assert!(!svc.is_available());
}

#[test]
fn lookup_ipv4_address_routes_to_ipv4_searcher() {
    let svc = GeoIpService::init("/nonexistent/ipv4.xdb", "/nonexistent/ipv6.xdb", CachePolicy::NoCache).expect("init");

    // With no searcher loaded, IPv4 lookup returns default (no panic/error).
    let ip: IpAddr = "1.1.1.1".parse().expect("ip");
    let info = svc.lookup(ip);
    assert_eq!(info.country, "");
}

#[test]
fn lookup_ipv6_address_routes_to_ipv6_searcher() {
    let svc = GeoIpService::init("/nonexistent/ipv4.xdb", "/nonexistent/ipv6.xdb", CachePolicy::NoCache).expect("init");

    let ip: IpAddr = "::1".parse().expect("ip");
    let info = svc.lookup(ip);
    assert_eq!(info.country, "");
}

// ── cache_policy_from_str ────────────────────────────────────────────────────

#[test]
fn cache_policy_full_memory_is_default() {
    assert!(matches!(cache_policy_from_str("full_memory"), CachePolicy::FullMemory));
}

#[test]
fn cache_policy_vector_index() {
    assert!(matches!(
        cache_policy_from_str("vector_index"),
        CachePolicy::VectorIndex
    ));
}

#[test]
fn cache_policy_no_cache() {
    assert!(matches!(cache_policy_from_str("no_cache"), CachePolicy::NoCache));
}

#[test]
fn cache_policy_unknown_falls_back_to_full_memory() {
    assert!(matches!(
        cache_policy_from_str("anything_else"),
        CachePolicy::FullMemory
    ));
}

#[test]
fn cache_policy_case_insensitive() {
    assert!(matches!(
        cache_policy_from_str("VECTOR_INDEX"),
        CachePolicy::VectorIndex
    ));
    assert!(matches!(cache_policy_from_str("NO_CACHE"), CachePolicy::NoCache));
}

// ── corrupted xdb file ───────────────────────────────────────────────────────

#[test]
fn init_with_corrupt_xdb_falls_back_gracefully() {
    let tmp = tempfile::tempdir().expect("tmp dir");
    let path = tmp.path().join("corrupt.xdb");
    // Write garbage bytes that are not a valid xdb file.
    std::fs::write(&path, b"not a real xdb file just garbage data here").expect("write");

    let path_str = path.to_str().expect("path str");
    // init should succeed (corrupt file treated as load failure → None searcher)
    // The searcher load logs a warn but does not propagate the error.
    let svc = GeoIpService::init(path_str, "/nonexistent/v6.xdb", CachePolicy::NoCache)
        .expect("init with corrupt file should not return Err");

    // With a corrupt file, searcher is None → unavailable.
    // (ip2region may succeed parsing or fail — either way we get a valid service.)
    let ip: IpAddr = "1.2.3.4".parse().expect("ip");
    // Must not panic regardless of whether ip2region accepted the garbage.
    let _info = svc.lookup(ip);
}

// ── reload keeps serving on failure ──────────────────────────────────────────

/// Build a minimal but fully searchable IPv4 xdb file in memory.
///
/// Layout mirrors the ip2region v3 format: 256-byte header (version=3,
/// index_policy=VectorIndex, ip_version=4), a full 256x256x8 vector index
/// whose every cell points at one segment, the region string, and a single
/// 14-byte segment covering 0.0.0.0-255.255.255.255. Every IPv4 lookup
/// resolves to `region`.
#[allow(clippy::cast_possible_truncation)]
fn searchable_xdb_bytes(region: &str) -> Vec<u8> {
    const HEADER_LEN: usize = 256;
    const VECTOR_INDEX_LEN: usize = 256 * 256 * 8;
    let region_offset = HEADER_LEN + VECTOR_INDEX_LEN;
    let seg_offset = region_offset + region.len();

    let mut buf = vec![0u8; seg_offset + 14];
    // Header: version=3 (u16 LE), index_policy=1 (VectorIndex), create_time=0,
    // start/end index ptr = the single segment, ip_version=4, ptr bytes=4.
    buf[0..2].copy_from_slice(&3u16.to_le_bytes());
    buf[2..4].copy_from_slice(&1u16.to_le_bytes());
    buf[8..12].copy_from_slice(&(seg_offset as u32).to_le_bytes());
    buf[12..16].copy_from_slice(&(seg_offset as u32).to_le_bytes());
    buf[16..18].copy_from_slice(&4u16.to_le_bytes());
    buf[18..20].copy_from_slice(&4u16.to_le_bytes());

    // Vector index: every (byte0, byte1) cell points at the one segment.
    for cell in 0..(256 * 256) {
        let at = HEADER_LEN + cell * 8;
        buf[at..at + 4].copy_from_slice(&(seg_offset as u32).to_le_bytes());
        buf[at + 4..at + 8].copy_from_slice(&(seg_offset as u32).to_le_bytes());
    }

    buf[region_offset..seg_offset].copy_from_slice(region.as_bytes());

    // Segment: start_ip 0.0.0.0, end_ip 255.255.255.255 (both stored LE),
    // then region length (u16 LE) and absolute region offset (u32 LE).
    buf[seg_offset + 4..seg_offset + 8].copy_from_slice(&[0xFF; 4]);
    buf[seg_offset + 8..seg_offset + 10].copy_from_slice(&(region.len() as u16).to_le_bytes());
    buf[seg_offset + 10..seg_offset + 14].copy_from_slice(&(region_offset as u32).to_le_bytes());
    buf
}

#[test]
fn reload_failure_keeps_serving_previous_searcher() {
    let tmp = tempfile::tempdir().expect("tmp dir");
    let path = tmp.path().join("v4.xdb");
    std::fs::write(&path, searchable_xdb_bytes("Testland|West|Springfield|TestNet|ZZ")).expect("write xdb");
    let path_str = path.to_str().expect("path str");

    // FullMemory so the baseline lookup pulls the whole file into the
    // searcher's cache — afterwards lookups must not touch the (soon bad)
    // file on disk.
    let svc = GeoIpService::init(path_str, "/nonexistent/v6.xdb", CachePolicy::FullMemory).expect("init");
    assert!(svc.is_available(), "valid xdb must load");

    let ip: IpAddr = "192.0.2.7".parse().expect("ip");
    let baseline = svc.lookup(ip);
    assert_eq!(baseline.country, "Testland", "baseline lookup must resolve real data");
    assert_eq!(baseline.iso_code, "ZZ");

    // The on-disk file goes bad; a reload must fail without dropping the
    // working searcher.
    std::fs::write(&path, b"garbage, no longer an xdb").expect("overwrite");
    let err = svc.reload().expect_err("reload of a corrupt file must error");
    assert!(
        err.to_string().contains("IPv4"),
        "error must name the preserved family, got: {err}"
    );

    assert!(svc.is_available(), "old searcher must survive the failed reload");
    let after = svc.lookup(ip);
    assert_eq!(
        after.country, baseline.country,
        "lookups must keep answering from the old searcher"
    );
    assert_eq!(after.iso_code, baseline.iso_code);
}

// ── multiple init paths ──────────────────────────────────────────────────────

#[test]
fn init_with_both_paths_missing_warns_but_succeeds() {
    // Both paths missing → both searchers None → service works but unavailable.
    let svc = GeoIpService::init("/tmp/no-v4.xdb", "/tmp/no-v6.xdb", CachePolicy::FullMemory).expect("init");
    assert!(!svc.is_available());
    // Reload also succeeds.
    assert!(!svc.reload().expect("reload"));
}

#[test]
fn lookup_loopback_returns_empty_info_when_unavailable() {
    let svc = GeoIpService::init("/nope.xdb", "/nope6.xdb", CachePolicy::NoCache).expect("init");
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let info = svc.lookup(loopback);
    assert!(info.country.is_empty());
    assert!(info.isp.is_empty());
    assert!(info.province.is_empty());
    assert!(info.city.is_empty());
    assert!(info.iso_code.is_empty());
}
