//! X-Forwarded-For chain sanity detector.
//!
//! Flags suspicious XFF patterns:
//! - Private IP appearing after public IP (proxy spoofing)
//! - Chain length > 5 (unusual, potential abuse)
//! - Duplicate IPs in chain (malformed or spoofed)
//!
//! Each violation adds +5, capped at +10 per request.

use std::net::IpAddr;

use crate::risk::state::{Contributor, ContributorKind};

/// Delta per XFF violation.
pub const XFF_VIOLATION_DELTA: i16 = 5;

/// Maximum total delta from XFF checks.
pub const XFF_MAX_DELTA: i16 = 10;

/// Maximum reasonable XFF chain length.
pub const MAX_CHAIN_LENGTH: usize = 5;

/// XFF violation types for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XffViolation {
    /// Private IP appeared after a public IP in the chain.
    PrivateAfterPublic,
    /// Chain length exceeds maximum.
    ChainTooLong,
    /// Duplicate IP in chain.
    DuplicateIp,
}

/// Check if an IP address is private/internal.
#[must_use]
#[allow(clippy::missing_const_for_fn)] // Uses non-const std methods
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                // 100.64.0.0/10 (CGNAT)
                || (v4.octets()[0] == 100 && (v4.octets()[1] & 0xC0) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || is_ula_v6(&v6),
    }
}

/// Check if IPv6 is Unique Local Address (`fc00::/7`).
const fn is_ula_v6(v6: &std::net::Ipv6Addr) -> bool {
    let first = v6.segments()[0];
    (first & 0xfe00) == 0xfc00
}

/// Parse XFF header value into a list of IPs.
/// Returns only successfully parsed IPs; invalid entries are skipped.
#[must_use]
pub fn parse_xff(xff_header: &str) -> Vec<IpAddr> {
    xff_header
        .split(',')
        .filter_map(|s| s.trim().parse::<IpAddr>().ok())
        .collect()
}

/// Detect XFF chain violations.
#[must_use]
pub fn detect_violations(ips: &[IpAddr]) -> Vec<XffViolation> {
    let mut violations = Vec::new();

    if ips.is_empty() {
        return violations;
    }

    // Check chain length
    if ips.len() > MAX_CHAIN_LENGTH {
        violations.push(XffViolation::ChainTooLong);
    }

    // Check for private-after-public pattern
    let mut seen_public = false;
    for ip in ips {
        if is_private_ip(*ip) {
            if seen_public {
                violations.push(XffViolation::PrivateAfterPublic);
                break;
            }
        } else {
            seen_public = true;
        }
    }

    // Check for duplicates
    let mut seen = std::collections::HashSet::new();
    for ip in ips {
        if !seen.insert(*ip) {
            violations.push(XffViolation::DuplicateIp);
            break;
        }
    }

    violations
}

/// Evaluate XFF chain and return a contributor if violations detected.
#[must_use]
pub fn evaluate(xff_header: Option<&str>, now_ms: i64) -> Option<Contributor> {
    let header = xff_header?;
    let ips = parse_xff(header);

    if ips.is_empty() {
        return None;
    }

    let violations = detect_violations(&ips);
    if violations.is_empty() {
        return None;
    }

    // +5 per violation, capped at +10
    #[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
    let delta = (violations.len() as i16 * XFF_VIOLATION_DELTA).min(XFF_MAX_DELTA);

    Some(Contributor::new(ContributorKind::Anomaly, delta, now_ms))
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn is_private_detects_rfc1918() {
        assert!(is_private_ip("10.0.0.1".parse().unwrap()));
        assert!(is_private_ip("172.16.0.1".parse().unwrap()));
        assert!(is_private_ip("192.168.1.1".parse().unwrap()));
        assert!(is_private_ip("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn is_private_detects_cgnat() {
        assert!(is_private_ip("100.64.0.1".parse().unwrap()));
        assert!(is_private_ip("100.127.255.254".parse().unwrap()));
    }

    #[test]
    fn is_private_public_ips() {
        assert!(!is_private_ip("8.8.8.8".parse().unwrap()));
        assert!(!is_private_ip("1.1.1.1".parse().unwrap()));
        assert!(!is_private_ip("203.0.113.1".parse().unwrap()));
    }

    #[test]
    fn parse_xff_valid() {
        let ips = parse_xff("203.0.113.1, 10.0.0.1, 192.168.1.1");
        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], "203.0.113.1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_xff_skips_invalid() {
        let ips = parse_xff("203.0.113.1, invalid, 10.0.0.1");
        assert_eq!(ips.len(), 2);
    }

    #[test]
    fn detect_private_after_public() {
        let ips: Vec<IpAddr> = vec![
            "203.0.113.1".parse().unwrap(),
            "10.0.0.1".parse().unwrap(), // Private after public!
        ];
        let violations = detect_violations(&ips);
        assert!(violations.contains(&XffViolation::PrivateAfterPublic));
    }

    #[test]
    fn detect_chain_too_long() {
        let ips: Vec<IpAddr> = (1..=6).map(|i| format!("203.0.113.{i}").parse().unwrap()).collect();
        let violations = detect_violations(&ips);
        assert!(violations.contains(&XffViolation::ChainTooLong));
    }

    #[test]
    fn detect_duplicate_ip() {
        let ips: Vec<IpAddr> = vec![
            "203.0.113.1".parse().unwrap(),
            "203.0.113.2".parse().unwrap(),
            "203.0.113.1".parse().unwrap(), // Duplicate!
        ];
        let violations = detect_violations(&ips);
        assert!(violations.contains(&XffViolation::DuplicateIp));
    }

    #[test]
    fn evaluate_clean_chain() {
        let result = evaluate(Some("203.0.113.1, 198.51.100.1"), 1000);
        assert!(result.is_none());
    }

    #[test]
    fn evaluate_violation_capped() {
        // Long chain with private-after-public and duplicate = 3 violations
        // But capped at +10
        let xff = "8.8.8.8, 10.0.0.1, 1.1.1.1, 2.2.2.2, 3.3.3.3, 8.8.8.8";
        let result = evaluate(Some(xff), 1000);
        assert!(result.is_some());
        assert_eq!(result.unwrap().delta, XFF_MAX_DELTA);
    }

    #[test]
    fn evaluate_no_header() {
        assert!(evaluate(None, 1000).is_none());
    }
}
