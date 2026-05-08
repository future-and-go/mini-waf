//! HTTP header sanity detector.
//!
//! Flags suspicious header patterns:
//! - Missing Accept header (browsers always send it)
//! - Missing Accept-Language (browsers always send it)
//! - Impossible Sec-Fetch-* combinations
//!
//! Each violation adds +5, capped at +15 per request.

use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::risk::state::{Contributor, ContributorKind};

/// Delta per header violation.
pub const HEADER_VIOLATION_DELTA: i16 = 5;

/// Maximum total delta from header checks.
pub const HEADER_MAX_DELTA: i16 = 15;

/// Header violation types for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderViolation {
    /// Missing Accept header.
    MissingAccept,
    /// Missing Accept-Language header.
    MissingAcceptLanguage,
    /// Sec-Fetch-Dest present but Sec-Fetch-Site missing.
    SecFetchIncomplete,
    /// Sec-Fetch-Mode incompatible with Sec-Fetch-Dest.
    SecFetchMismatch,
}

/// Detect header sanity violations.
///
/// Headers map should have lowercase keys for consistent matching.
#[must_use]
pub fn detect_violations<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
    user_agent: &str,
) -> Vec<HeaderViolation> {
    let mut violations = Vec::new();

    // Only check browser-like user agents (skip curl, bots, etc.)
    if !looks_like_browser(user_agent) {
        return violations;
    }

    // Check for missing Accept header
    if !headers.contains_key("accept") {
        violations.push(HeaderViolation::MissingAccept);
    }

    // Check for missing Accept-Language header
    if !headers.contains_key("accept-language") {
        violations.push(HeaderViolation::MissingAcceptLanguage);
    }

    // Check Sec-Fetch-* consistency
    if let Some(violation) = check_sec_fetch_consistency(headers) {
        violations.push(violation);
    }

    violations
}

/// Check if User-Agent looks like a real browser.
fn looks_like_browser(ua: &str) -> bool {
    let ua_lower = ua.to_lowercase();
    (ua_lower.contains("mozilla/") || ua_lower.contains("chrome/") || ua_lower.contains("safari/"))
        && !ua_lower.contains("bot")
        && !ua_lower.contains("crawler")
        && !ua_lower.contains("spider")
        && !ua_lower.contains("curl")
        && !ua_lower.contains("wget")
        && !ua_lower.contains("python")
        && !ua_lower.contains("java/")
        && !ua_lower.contains("go-http")
}

/// Check Sec-Fetch-* header consistency.
fn check_sec_fetch_consistency<S: BuildHasher>(headers: &HashMap<String, String, S>) -> Option<HeaderViolation> {
    let dest = headers.get("sec-fetch-dest");
    let site = headers.get("sec-fetch-site");
    let mode = headers.get("sec-fetch-mode");

    // If Sec-Fetch-Dest is present, Sec-Fetch-Site should also be present
    // (browsers always send both together)
    if dest.is_some() && site.is_none() {
        return Some(HeaderViolation::SecFetchIncomplete);
    }

    // Check mode/dest compatibility
    if let (Some(dest_val), Some(mode_val)) = (dest, mode)
        && is_impossible_sec_fetch_combo(dest_val, mode_val)
    {
        return Some(HeaderViolation::SecFetchMismatch);
    }

    None
}

/// Check for impossible Sec-Fetch-Dest + Sec-Fetch-Mode combinations.
fn is_impossible_sec_fetch_combo(dest: &str, mode: &str) -> bool {
    matches!(
        (dest, mode),
        ("document", "no-cors")
            | ("script" | "style" | "worker" | "sharedworker", "navigate")
            | ("iframe", "cors" | "no-cors" | "same-origin")
    )
}

/// Evaluate header sanity and return a contributor if violations detected.
#[must_use]
pub fn evaluate<S: BuildHasher>(
    headers: &HashMap<String, String, S>,
    user_agent: &str,
    now_ms: i64,
) -> Option<Contributor> {
    let violations = detect_violations(headers, user_agent);

    if violations.is_empty() {
        return None;
    }

    // +5 per violation, capped at +15
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let delta = (violations.len() as i16 * HEADER_VIOLATION_DELTA).min(HEADER_MAX_DELTA);

    Some(Contributor::new(ContributorKind::Anomaly, delta, now_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn browser_ua() -> String {
        "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0.0.0 Safari/537.36".to_string()
    }

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn detect_missing_accept() {
        let headers = make_headers(&[("accept-language", "en-US")]);
        let violations = detect_violations(&headers, &browser_ua());
        assert!(violations.contains(&HeaderViolation::MissingAccept));
    }

    #[test]
    fn detect_missing_accept_language() {
        let headers = make_headers(&[("accept", "text/html")]);
        let violations = detect_violations(&headers, &browser_ua());
        assert!(violations.contains(&HeaderViolation::MissingAcceptLanguage));
    }

    #[test]
    fn detect_sec_fetch_incomplete() {
        let headers = make_headers(&[
            ("accept", "text/html"),
            ("accept-language", "en-US"),
            ("sec-fetch-dest", "document"),
            // Missing sec-fetch-site!
        ]);
        let violations = detect_violations(&headers, &browser_ua());
        assert!(violations.contains(&HeaderViolation::SecFetchIncomplete));
    }

    #[test]
    fn detect_sec_fetch_mismatch() {
        let headers = make_headers(&[
            ("accept", "text/html"),
            ("accept-language", "en-US"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "no-cors"), // Impossible with document!
        ]);
        let violations = detect_violations(&headers, &browser_ua());
        assert!(violations.contains(&HeaderViolation::SecFetchMismatch));
    }

    #[test]
    fn skip_non_browser_ua() {
        let headers = make_headers(&[]); // Missing everything
        let violations = detect_violations(&headers, "curl/7.88.1");
        assert!(violations.is_empty());
    }

    #[test]
    fn clean_headers_no_violations() {
        let headers = make_headers(&[
            ("accept", "text/html,application/xhtml+xml"),
            ("accept-language", "en-US,en;q=0.9"),
            ("sec-fetch-dest", "document"),
            ("sec-fetch-site", "same-origin"),
            ("sec-fetch-mode", "navigate"),
        ]);
        let violations = detect_violations(&headers, &browser_ua());
        assert!(violations.is_empty());
    }

    #[test]
    fn evaluate_returns_capped_delta() {
        // All violations: missing accept, missing accept-language, sec-fetch incomplete
        let headers = make_headers(&[("sec-fetch-dest", "document")]);
        let result = evaluate(&headers, &browser_ua(), 1000);
        assert!(result.is_some());
        let contrib = result.unwrap();
        assert_eq!(contrib.delta, HEADER_MAX_DELTA);
    }

    #[test]
    fn evaluate_no_violations() {
        let headers = make_headers(&[("accept", "text/html"), ("accept-language", "en-US")]);
        let result = evaluate(&headers, &browser_ua(), 1000);
        assert!(result.is_none());
    }
}
