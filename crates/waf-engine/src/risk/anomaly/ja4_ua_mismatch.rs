//! JA4 ↔ User-Agent mismatch detector.
//!
//! Detects when TLS fingerprint (JA4) indicates one browser family but the
//! User-Agent header claims another. Example: Chrome JA4 with Firefox UA.
//!
//! Conservative initial table — only obvious impossible pairs flagged.
//! Unknown JA4 or unknown UA → no signal (silent pass).

use crate::risk::state::{Contributor, ContributorKind};

/// Risk delta for JA4↔UA mismatch.
pub const JA4_UA_MISMATCH_DELTA: i16 = 20;

/// Known Chrome cipher hashes (truncated SHA256 of sorted ciphers).
const CHROME_CIPHER_HASHES: &[&str] = &[
    "a0e9f5d5c5be", // Common Chrome pattern
    "d9f3db469cc8", // Chrome on Windows
    "e5627efa2ab1", // Chrome on macOS
];

/// Known Firefox cipher hashes.
const FIREFOX_CIPHER_HASHES: &[&str] = &[
    "579ccef312d3", // Firefox stable
    "2bab5d9fbbd5", // Firefox ESR
    "afcc4d25d72e", // Firefox on Linux
];

/// Known Safari cipher hashes.
const SAFARI_CIPHER_HASHES: &[&str] = &[
    "e06a8f7f3f73", // Safari macOS
    "7e694882a09a", // Safari iOS
];

/// Browser family derived from JA4 fingerprint patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ja4Family {
    Chrome,
    Firefox,
    Safari,
    Edge,
    // Future: Curl, Python, etc.
}

/// Browser family derived from User-Agent string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UaFamily {
    Chrome,
    Firefox,
    Safari,
    Edge,
}

/// Extract browser family from JA4 fingerprint.
///
/// JA4 format: `<JA4_a>_<JA4_b>_<JA4_c>` where `JA4_a` is 10 chars.
/// We examine the ALPN pair (last 2 chars of `JA4_a`) and cipher patterns.
#[must_use]
pub fn ja4_family(ja4: &str) -> Option<Ja4Family> {
    // JA4 must have at least the 'a' section (10 chars)
    if ja4.len() < 10 {
        return None;
    }

    let ja4_a = &ja4[..10];
    let alpn = &ja4_a[8..10];

    // Get the 'b' section (cipher hash) if available
    let parts: Vec<&str> = ja4.split('_').collect();
    let cipher_hash = parts.get(1)?;

    if CHROME_CIPHER_HASHES.contains(cipher_hash) {
        return Some(Ja4Family::Chrome);
    }
    if FIREFOX_CIPHER_HASHES.contains(cipher_hash) {
        return Some(Ja4Family::Firefox);
    }
    if SAFARI_CIPHER_HASHES.contains(cipher_hash) {
        return Some(Ja4Family::Safari);
    }

    // Fallback: check ALPN patterns
    // Chrome typically negotiates h2
    if alpn == "h2" && ja4_a.contains("13") {
        // TLS 1.3 + h2 is common for modern browsers, not conclusive alone
        return None;
    }

    None
}

/// Extract browser family from User-Agent string.
#[must_use]
pub fn ua_family(ua: &str) -> Option<UaFamily> {
    let ua_lower = ua.to_lowercase();

    // Order matters: Edge contains "Chrome", Safari contains "Safari" but also Chrome on iOS
    if ua_lower.contains("edg/") || ua_lower.contains("edge/") {
        return Some(UaFamily::Edge);
    }
    if ua_lower.contains("firefox/") {
        return Some(UaFamily::Firefox);
    }
    // Chrome check must come before Safari (Chrome UA contains both)
    if ua_lower.contains("chrome/") && !ua_lower.contains("chromium/") {
        return Some(UaFamily::Chrome);
    }
    if ua_lower.contains("safari/") && !ua_lower.contains("chrome/") {
        return Some(UaFamily::Safari);
    }

    None
}

/// Check if JA4 and UA families are an impossible combination.
#[must_use]
pub const fn is_mismatch(ja4_fam: Ja4Family, ua_fam: UaFamily) -> bool {
    // Conservative list of impossible pairs
    matches!(
        (ja4_fam, ua_fam),
        // Chrome or Safari TLS with Firefox UA
        (Ja4Family::Chrome | Ja4Family::Safari, UaFamily::Firefox)
            // Firefox or Safari TLS with Chrome UA
            | (Ja4Family::Firefox | Ja4Family::Safari, UaFamily::Chrome)
            // Firefox or Chrome TLS with Safari UA
            | (Ja4Family::Firefox | Ja4Family::Chrome, UaFamily::Safari)
    )
}

/// Evaluate JA4↔UA mismatch and return a contributor if detected.
#[must_use]
pub fn evaluate(ja4: Option<&str>, user_agent: &str, now_ms: i64) -> Option<Contributor> {
    let ja4_str = ja4?;
    let ja4_fam = ja4_family(ja4_str)?;
    let ua_fam = ua_family(user_agent)?;

    if is_mismatch(ja4_fam, ua_fam) {
        Some(Contributor::new(
            ContributorKind::Anomaly,
            JA4_UA_MISMATCH_DELTA,
            now_ms,
        ))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ua_family_detection() {
        assert_eq!(
            ua_family("Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0.0.0 Safari/537.36"),
            Some(UaFamily::Chrome)
        );
        assert_eq!(
            ua_family("Mozilla/5.0 (Windows NT 10.0; rv:121.0) Gecko/20100101 Firefox/121.0"),
            Some(UaFamily::Firefox)
        );
        assert_eq!(
            ua_family("Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Safari/605.1.15"),
            Some(UaFamily::Safari)
        );
        assert_eq!(
            ua_family("Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Edg/120.0.0.0"),
            Some(UaFamily::Edge)
        );
        assert_eq!(ua_family("curl/7.88.1"), None);
    }

    #[test]
    fn mismatch_impossible_pairs() {
        assert!(is_mismatch(Ja4Family::Chrome, UaFamily::Firefox));
        assert!(is_mismatch(Ja4Family::Firefox, UaFamily::Chrome));
        assert!(is_mismatch(Ja4Family::Safari, UaFamily::Firefox));
    }

    #[test]
    fn mismatch_compatible_pairs() {
        // Same family is always compatible
        assert!(!is_mismatch(Ja4Family::Chrome, UaFamily::Chrome));
        assert!(!is_mismatch(Ja4Family::Firefox, UaFamily::Firefox));
        // Edge is Chromium-based, so Chrome TLS with Edge UA is fine
        assert!(!is_mismatch(Ja4Family::Chrome, UaFamily::Edge));
    }

    #[test]
    fn evaluate_no_ja4_returns_none() {
        assert!(evaluate(None, "Mozilla/5.0 Chrome/120", 1000).is_none());
    }

    #[test]
    fn evaluate_unknown_families_returns_none() {
        // Unknown JA4 pattern
        assert!(evaluate(Some("t12d0505h2_unknown_hash"), "Mozilla/5.0 Chrome/120", 1000).is_none());
    }

    #[test]
    fn evaluate_mismatch_returns_contributor() {
        // Use known Firefox cipher hash with Chrome UA
        let ja4 = "t13d1012h2_579ccef312d3_abcdef123456";
        let ua = "Mozilla/5.0 (Windows NT 10.0; Win64) Chrome/120.0.0.0 Safari/537.36";

        let result = evaluate(Some(ja4), ua, 1000);
        assert!(result.is_some());
        let contrib = result.unwrap();
        assert_eq!(contrib.delta, JA4_UA_MISMATCH_DELTA);
        assert!(matches!(contrib.kind, ContributorKind::Anomaly));
    }
}
