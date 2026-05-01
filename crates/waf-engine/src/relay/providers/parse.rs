//! FR-007 phase-02 — XFF parse + real-IP derivation helpers.
//!
//! Pure functions, no I/O. Hard caps enforced **before** allocation-heavy
//! work (`DoS` hardening per brainstorm `§6`).

use std::net::IpAddr;
use std::str::FromStr;

use http::{HeaderMap, HeaderName};
use ipnet::IpNet;

/// Per brainstorm §4.8 — reject oversize headers before parsing.
pub const MAX_HEADER_BYTES: usize = 8192;
pub const MAX_CHAIN_ENTRIES: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct ParsedChain {
    /// Successfully parsed entries (empty if any error flag set).
    pub entries: Vec<IpAddr>,
    pub too_long_bytes: bool,
    pub too_long_count: bool,
    pub malformed: bool,
}

impl ParsedChain {
    #[must_use]
    pub const fn has_error(&self) -> bool {
        self.too_long_bytes || self.too_long_count || self.malformed
    }
}

/// Concatenate folded headers with `,` (RFC 7230 §3.2.2), enforce caps,
/// split, trim, and parse each token.
pub fn parse_xff_chain(headers: &HeaderMap, header_names: &[HeaderName]) -> ParsedChain {
    let mut combined = String::new();
    let mut total_bytes: usize = 0;

    for name in header_names {
        for v in headers.get_all(name) {
            total_bytes = total_bytes.saturating_add(v.len());
            if total_bytes > MAX_HEADER_BYTES {
                return ParsedChain {
                    too_long_bytes: true,
                    ..Default::default()
                };
            }
            match v.to_str() {
                Ok(s) => {
                    if !combined.is_empty() {
                        combined.push(',');
                    }
                    combined.push_str(s);
                }
                Err(_) => {
                    return ParsedChain {
                        malformed: true,
                        ..Default::default()
                    };
                }
            }
        }
    }

    if combined.is_empty() {
        return ParsedChain::default();
    }

    let raw: Vec<&str> = combined.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();

    if raw.len() > MAX_CHAIN_ENTRIES {
        return ParsedChain {
            too_long_count: true,
            ..Default::default()
        };
    }

    let mut entries = Vec::with_capacity(raw.len());
    for token in raw {
        match parse_token(token) {
            Some(ip) => entries.push(ip),
            None => {
                return ParsedChain {
                    malformed: true,
                    ..Default::default()
                };
            }
        }
    }

    ParsedChain {
        entries,
        ..Default::default()
    }
}

/// Parse a single XFF token: handles IPv6 brackets, IPv4:port, zone IDs,
/// and stray quoting per RFC 7239 (Forwarded grammar leaks into the wild).
fn parse_token(raw: &str) -> Option<IpAddr> {
    let s = raw.trim().trim_matches('"');
    if let Some(rest) = s.strip_prefix('[') {
        // [addr] or [addr]:port — strip until ']'.
        let end = rest.find(']')?;
        let addr = strip_zone(&rest[..end]);
        return IpAddr::from_str(addr).ok();
    }
    // Disambiguate IPv4:port vs unbracketed IPv6 by colon count.
    let colons = s.bytes().filter(|b| *b == b':').count();
    let candidate = if colons == 1 {
        s.split(':').next().unwrap_or(s)
    } else {
        s
    };
    IpAddr::from_str(strip_zone(candidate)).ok()
}

fn strip_zone(s: &str) -> &str {
    s.split('%').next().unwrap_or(s)
}

#[derive(Debug, Clone, Copy)]
pub struct DeriveOutcome {
    pub real_ip: IpAddr,
    pub stripped_count: u8,
    pub spoof_private_mid_chain: bool,
}

/// Walk right→left, strip trusted CIDRs.
///
/// First non-trusted entry is `real_ip`; if all trusted (or chain empty)
/// fall back to `peer_ip`. Spoof flag: any entry up to and including the
/// `real_ip` index that is private/loopback/link-local — those have no
/// business beyond the trusted tail per brainstorm `§6` risk #1.
pub fn derive_real_ip(chain: &[IpAddr], trusted: &[IpNet], peer_ip: IpAddr) -> DeriveOutcome {
    if chain.is_empty() {
        return DeriveOutcome {
            real_ip: peer_ip,
            stripped_count: 0,
            spoof_private_mid_chain: false,
        };
    }

    let mut stripped: u8 = 0;
    let mut real_idx: Option<usize> = None;
    for (i, ip) in chain.iter().enumerate().rev() {
        if trusted.iter().any(|n| n.contains(ip)) {
            stripped = stripped.saturating_add(1);
        } else {
            real_idx = Some(i);
            break;
        }
    }

    real_idx.map_or(
        DeriveOutcome {
            real_ip: peer_ip,
            stripped_count: stripped,
            spoof_private_mid_chain: false,
        },
        |i| {
            let head = chain.get(..=i).unwrap_or(chain);
            let spoof = head.iter().any(is_private_like);
            let real_ip = head.last().copied().unwrap_or(peer_ip);
            DeriveOutcome {
                real_ip,
                stripped_count: stripped,
                spoof_private_mid_chain: spoof,
            }
        },
    )
}

const fn is_private_like(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified(),
        IpAddr::V6(v6) => {
            let s0 = v6.segments()[0];
            v6.is_loopback()
                || v6.is_unspecified()
                || (s0 & 0xfe00) == 0xfc00 // ULA fc00::/7
                || (s0 & 0xffc0) == 0xfe80 // link-local fe80::/10
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn xff() -> HeaderName {
        HeaderName::from_static("x-forwarded-for")
    }

    fn hdr(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(xff(), HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn empty_header_yields_empty_chain() {
        let p = parse_xff_chain(&HeaderMap::new(), &[xff()]);
        assert!(p.entries.is_empty());
        assert!(!p.has_error());
    }

    #[test]
    fn single_ipv4() {
        let p = parse_xff_chain(&hdr(&["1.2.3.4"]), &[xff()]);
        assert_eq!(p.entries, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn over_entry_cap_flags_too_long() {
        let many: Vec<String> = (0..40).map(|i| format!("10.0.0.{i}")).collect();
        let joined = many.join(", ");
        let p = parse_xff_chain(&hdr(&[joined.as_str()]), &[xff()]);
        assert!(p.too_long_count);
        assert!(p.entries.is_empty());
    }

    #[test]
    fn over_byte_cap_flags_too_long() {
        let big = "1".repeat(MAX_HEADER_BYTES + 10);
        let p = parse_xff_chain(&hdr(&[big.as_str()]), &[xff()]);
        assert!(p.too_long_bytes);
    }

    #[test]
    fn ipv6_bracketed_with_port() {
        let p = parse_xff_chain(&hdr(&["[2001:db8::1]:443"]), &[xff()]);
        assert_eq!(p.entries, vec![IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap())]);
    }

    #[test]
    fn ipv6_zone_id_stripped() {
        let p = parse_xff_chain(&hdr(&["fe80::1%eth0"]), &[xff()]);
        assert_eq!(p.entries, vec![IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap())]);
    }

    #[test]
    fn ipv4_with_port_stripped() {
        let p = parse_xff_chain(&hdr(&["1.2.3.4:8080"]), &[xff()]);
        assert_eq!(p.entries, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn malformed_token_flags_error() {
        let p = parse_xff_chain(&hdr(&["1.2.3.4, not-an-ip"]), &[xff()]);
        assert!(p.malformed);
        assert!(p.entries.is_empty());
    }

    #[test]
    fn folded_headers_concatenated() {
        let p = parse_xff_chain(&hdr(&["1.1.1.1", "2.2.2.2, 3.3.3.3"]), &[xff()]);
        assert_eq!(p.entries.len(), 3);
    }

    #[test]
    fn spoof_private_mid_chain() {
        let chain: Vec<IpAddr> = ["1.2.3.4", "10.0.0.1", "5.6.7.8"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        let out = derive_real_ip(&chain, &trusted, peer);
        assert_eq!(out.real_ip, "5.6.7.8".parse::<IpAddr>().unwrap());
        assert_eq!(out.stripped_count, 0);
        assert!(out.spoof_private_mid_chain);
    }

    #[test]
    fn all_trusted_falls_back_to_peer() {
        let chain: Vec<IpAddr> = ["10.0.0.1", "10.0.0.2"].iter().map(|s| s.parse().unwrap()).collect();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        let out = derive_real_ip(&chain, &trusted, peer);
        assert_eq!(out.real_ip, peer);
        assert_eq!(out.stripped_count, 2);
        assert!(!out.spoof_private_mid_chain);
    }

    #[test]
    fn empty_chain_returns_peer() {
        let trusted: Vec<IpNet> = vec![];
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        let out = derive_real_ip(&[], &trusted, peer);
        assert_eq!(out.real_ip, peer);
    }

    #[test]
    fn trusted_tail_strips_then_real_ip() {
        let chain: Vec<IpAddr> = ["1.2.3.4", "10.0.0.1"].iter().map(|s| s.parse().unwrap()).collect();
        let trusted: Vec<IpNet> = vec!["10.0.0.0/8".parse().unwrap()];
        let peer: IpAddr = "9.9.9.9".parse().unwrap();
        let out = derive_real_ip(&chain, &trusted, peer);
        assert_eq!(out.real_ip, "1.2.3.4".parse::<IpAddr>().unwrap());
        assert_eq!(out.stripped_count, 1);
        assert!(!out.spoof_private_mid_chain);
    }
}
