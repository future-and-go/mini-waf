//! FR-025 Phase 5: Anomaly detector combination tests.
//!
//! Verifies each detector emits correct deltas and that combinations
//! accumulate properly without exceeding individual caps.

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
    clippy::doc_markdown,
    clippy::missing_const_for_fn,
    clippy::items_after_statements,
    clippy::format_push_string,
    clippy::err_expect,
    clippy::needless_pass_by_value,
    clippy::needless_raw_string_hashes,
    clippy::uninlined_format_args,
    unused_imports
)]

use std::collections::HashMap;

use crate::risk::anomaly::header_sanity::{self, HEADER_MAX_DELTA, HEADER_VIOLATION_DELTA};
use crate::risk::anomaly::ja4_ua_mismatch::{self, JA4_UA_MISMATCH_DELTA};
use crate::risk::anomaly::xff_chain::{self, XFF_MAX_DELTA, XFF_VIOLATION_DELTA};
use crate::risk::anomaly::{AnomalyCtx, AnomalyLayer};
use crate::risk::state::ContributorKind;

fn browser_ua() -> String {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36".to_string()
}

fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

// ─────────────────────────────────────────────────────────────────────────────
// JA4↔UA Mismatch Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn ja4_ua_mismatch_delta_is_20() {
    assert_eq!(JA4_UA_MISMATCH_DELTA, 20);
}

#[test]
fn ja4_ua_mismatch_chrome_ja4_with_firefox_ua() {
    // Known Chrome cipher hash with Firefox UA
    let ja4 = "t13d1012h2_a0e9f5d5c5be_abcdef123456";
    let ua = "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0";

    let result = ja4_ua_mismatch::evaluate(Some(ja4), ua, 1000);
    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, JA4_UA_MISMATCH_DELTA);
}

#[test]
fn ja4_ua_mismatch_firefox_ja4_with_chrome_ua() {
    // Known Firefox cipher hash with Chrome UA
    let ja4 = "t13d1012h2_579ccef312d3_abcdef123456";
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0.0.0 Safari/537.36";

    let result = ja4_ua_mismatch::evaluate(Some(ja4), ua, 1000);
    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, JA4_UA_MISMATCH_DELTA);
}

#[test]
fn ja4_ua_mismatch_matching_families_no_signal() {
    // Chrome JA4 with Chrome UA — should NOT flag
    let ja4 = "t13d1012h2_a0e9f5d5c5be_abcdef123456";
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0.0.0 Safari/537.36";

    let result = ja4_ua_mismatch::evaluate(Some(ja4), ua, 1000);
    assert!(result.is_none());
}

#[test]
fn ja4_ua_mismatch_unknown_ja4_no_signal() {
    // Unknown JA4 hash — should NOT flag (conservative)
    let ja4 = "t13d1012h2_unknown12hash_abcdef123456";
    let ua = "Mozilla/5.0 Firefox/121.0";

    let result = ja4_ua_mismatch::evaluate(Some(ja4), ua, 1000);
    assert!(result.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// XFF Chain Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn xff_chain_delta_is_5_capped_at_10() {
    assert_eq!(XFF_VIOLATION_DELTA, 5);
    assert_eq!(XFF_MAX_DELTA, 10);
}

#[test]
fn xff_chain_private_after_public() {
    let xff = "203.0.113.1, 10.0.0.1"; // Public then private = suspicious
    let result = xff_chain::evaluate(Some(xff), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, XFF_VIOLATION_DELTA);
}

#[test]
fn xff_chain_too_long() {
    // 6 IPs = too long
    let xff = "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6";
    let result = xff_chain::evaluate(Some(xff), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, XFF_VIOLATION_DELTA);
}

#[test]
fn xff_chain_duplicate_ip() {
    let xff = "203.0.113.1, 198.51.100.1, 203.0.113.1"; // Duplicate
    let result = xff_chain::evaluate(Some(xff), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, XFF_VIOLATION_DELTA);
}

#[test]
fn xff_chain_multiple_violations_capped() {
    // Long chain + private-after-public + duplicate = 3 violations
    // But capped at 10
    let xff = "8.8.8.8, 10.0.0.1, 1.1.1.1, 2.2.2.2, 3.3.3.3, 8.8.8.8";
    let result = xff_chain::evaluate(Some(xff), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, XFF_MAX_DELTA);
}

#[test]
fn xff_chain_clean_returns_none() {
    let xff = "203.0.113.1, 198.51.100.1, 192.0.2.1";
    let result = xff_chain::evaluate(Some(xff), 1000);
    assert!(result.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Header Sanity Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn header_sanity_delta_is_5_capped_at_15() {
    assert_eq!(HEADER_VIOLATION_DELTA, 5);
    assert_eq!(HEADER_MAX_DELTA, 15);
}

#[test]
fn header_sanity_missing_accept() {
    let headers = make_headers(&[("accept-language", "en-US")]);
    let result = header_sanity::evaluate(&headers, &browser_ua(), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, HEADER_VIOLATION_DELTA);
}

#[test]
fn header_sanity_missing_accept_language() {
    let headers = make_headers(&[("accept", "text/html")]);
    let result = header_sanity::evaluate(&headers, &browser_ua(), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, HEADER_VIOLATION_DELTA);
}

#[test]
fn header_sanity_missing_both_capped() {
    let headers = make_headers(&[("sec-fetch-dest", "document")]); // Also incomplete sec-fetch
    let result = header_sanity::evaluate(&headers, &browser_ua(), 1000);

    assert!(result.is_some());
    // Missing accept + missing accept-language + sec-fetch incomplete = 3 * 5 = 15 (capped)
    assert_eq!(result.unwrap().delta, HEADER_MAX_DELTA);
}

#[test]
fn header_sanity_sec_fetch_impossible_combo() {
    let headers = make_headers(&[
        ("accept", "text/html"),
        ("accept-language", "en-US"),
        ("sec-fetch-dest", "document"),
        ("sec-fetch-site", "same-origin"),
        ("sec-fetch-mode", "no-cors"), // Impossible with document
    ]);
    let result = header_sanity::evaluate(&headers, &browser_ua(), 1000);

    assert!(result.is_some());
    assert_eq!(result.unwrap().delta, HEADER_VIOLATION_DELTA);
}

#[test]
fn header_sanity_skips_non_browser() {
    let headers = make_headers(&[]); // Missing everything
    let result = header_sanity::evaluate(&headers, "curl/7.88.1", 1000);
    assert!(result.is_none());
}

#[test]
fn header_sanity_clean_returns_none() {
    let headers = make_headers(&[
        ("accept", "text/html,application/xhtml+xml"),
        ("accept-language", "en-US,en;q=0.9"),
    ]);
    let result = header_sanity::evaluate(&headers, &browser_ua(), 1000);
    assert!(result.is_none());
}

// ─────────────────────────────────────────────────────────────────────────────
// Combined Anomaly Layer Tests
// ─────────────────────────────────────────────────────────────────────────────

#[test]
fn anomaly_layer_combines_multiple_detectors() {
    let layer = AnomalyLayer::new();
    let headers = make_headers(&[]); // Missing accept + accept-language
    let ua = browser_ua();
    let xff = "8.8.8.8, 10.0.0.1"; // Private after public

    let ctx = AnomalyCtx::new(None, &ua, Some(xff), &headers);
    let contributors = layer.evaluate(&ctx, 1000);

    // Should have header sanity + XFF violations
    assert!(contributors.len() >= 2);

    // Verify all are Anomaly type
    for c in &contributors {
        assert!(matches!(c.kind, ContributorKind::Anomaly));
    }
}

#[test]
fn anomaly_layer_all_three_detectors() {
    let layer = AnomalyLayer::new();
    let headers = make_headers(&[]); // Missing headers
    let ua = "Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0";
    let xff = "8.8.8.8, 10.0.0.1"; // Private after public
    let ja4 = "t13d1012h2_a0e9f5d5c5be_abcdef123456"; // Chrome JA4 with Firefox UA

    let ctx = AnomalyCtx::new(Some(ja4), ua, Some(xff), &headers);
    let contributors = layer.evaluate(&ctx, 1000);

    // All three detectors should fire
    assert_eq!(contributors.len(), 3);

    // Calculate total delta
    let total: i16 = contributors.iter().map(|c| c.delta).sum();
    // JA4 mismatch (20) + XFF (5) + Header (10 for missing both) = 35
    assert!(total >= 30, "Total delta {} should be >= 30", total);
}

#[test]
fn anomaly_layer_no_anomalies_empty_list() {
    let layer = AnomalyLayer::new();
    let headers = make_headers(&[("accept", "text/html"), ("accept-language", "en-US")]);
    let ua = browser_ua();

    let ctx = AnomalyCtx::new(None, &ua, None, &headers);
    let contributors = layer.evaluate(&ctx, 1000);

    assert!(contributors.is_empty());
}
