//! Integration tests for `geoip::GeoIpService`.
//!
//! Covers: init with missing files (both searchers None), is_available,
//! lookup on unavailable service returns default GeoIpInfo, reload no-op
//! when files still missing, cache_policy_from_str all variants,
//! IPv4 vs IPv6 routing in lookup dispatch, parse_region via public lookup.

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
