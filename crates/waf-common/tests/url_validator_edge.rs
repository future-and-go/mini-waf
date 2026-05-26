//! Edge-case coverage for `waf_common::url_validator` SSRF guard.

use waf_common::url_validator::{
    UrlValidationError, validate_public_url, validate_public_url_with_ips, validate_scheme_only,
};

#[test]
fn rejects_uppercase_scheme_other_than_http_s() {
    // url::Url normalises scheme to lowercase, so "HTTPS://" is fine.
    assert!(validate_public_url("HTTPS://1.1.1.1/").is_ok());
    // But "FTP" must be rejected.
    let err = validate_public_url("FTP://example.com/").unwrap_err();
    assert!(matches!(err, UrlValidationError::DisallowedScheme(_)));
}

#[test]
fn rejects_zero_address_v4_and_v6() {
    assert!(validate_public_url("http://0.0.0.0/").is_err());
    assert!(validate_public_url("http://[::]/").is_err());
}

#[test]
fn rejects_documentation_v6() {
    // 2001:db8::/32 — RFC 3849 documentation prefix.
    assert!(validate_public_url("http://[2001:db8::1]/").is_err());
}

#[test]
fn rejects_v4_v6_translation_prefix() {
    // 64:ff9b::/96 — RFC 6052 NAT64 prefix.
    assert!(validate_public_url("http://[64:ff9b::1]/").is_err());
}

#[test]
fn rejects_ipv4_multicast_and_broadcast() {
    assert!(validate_public_url("http://224.0.0.1/").is_err());
    assert!(validate_public_url("http://255.255.255.255/").is_err());
}

#[test]
fn rejects_ipv6_multicast() {
    // ff00::/8 — IPv6 multicast.
    assert!(validate_public_url("http://[ff00::1]/").is_err());
}

#[test]
fn rejects_aws_metadata_hostname() {
    assert!(validate_public_url("http://169.254.169.254/").is_err());
}

#[test]
fn rejects_alibaba_metadata_literal() {
    assert!(validate_public_url("http://100.100.100.200/").is_err());
}

#[test]
fn rejects_extra_blocklisted_names() {
    for name in [
        "http://localhost.localdomain/",
        "http://ip6-localhost/",
        "http://ip6-loopback/",
        "http://broadcasthost/",
    ] {
        assert!(validate_public_url(name).is_err(), "{name} must be blocked");
    }
}

#[test]
fn rejects_blocklist_case_insensitively() {
    assert!(validate_public_url("http://LOCALHOST/").is_err());
    assert!(validate_public_url("http://Metadata.Google.Internal/").is_err());
}

#[test]
fn rejects_unresolvable_hostname_fail_closed() {
    // RFC 6761 reserves .invalid TLD — guaranteed to never resolve.
    let err = validate_public_url("http://surely-nobody-owns-this.invalid/").unwrap_err();
    match err {
        UrlValidationError::BlockedHost(_, msg) => {
            assert!(msg.contains("could not be resolved") || msg.contains("safe"));
        }
        other => panic!("expected BlockedHost, got {other:?}"),
    }
}

#[test]
fn returns_empty_resolved_for_ip_literals() {
    let (_url, addrs) = validate_public_url_with_ips("https://1.1.1.1/").unwrap();
    assert!(addrs.is_empty());
    let (_url, addrs) = validate_public_url_with_ips("https://[2606:4700:4700::1111]/").unwrap();
    assert!(addrs.is_empty());
}

#[test]
fn url_with_no_host_rejected() {
    // "data:text/plain,hi" — no host. But scheme check rejects first; pick a
    // scheme that passes scheme but has no host.
    let r = validate_public_url("http:///nohost");
    assert!(r.is_err());
}

#[test]
fn parse_error_propagates() {
    let err = validate_public_url("http://[bad-ipv6").unwrap_err();
    assert!(matches!(err, UrlValidationError::Parse(_)));
}

#[test]
fn blocked_host_error_display_contains_host() {
    let err = validate_public_url("http://10.0.0.1/").unwrap_err();
    let s = err.to_string();
    assert!(s.contains("blocked host"));
    assert!(s.contains("10.0.0.1"));
}

#[test]
fn disallowed_scheme_error_display() {
    let err = validate_public_url("gopher://example.com/").unwrap_err();
    assert!(err.to_string().contains("gopher"));
}

#[test]
fn parse_error_display() {
    let err = validate_public_url("not::a::url").unwrap_err();
    // Just confirm Display works without panicking.
    let _ = err.to_string();
}

#[test]
fn scheme_only_parse_error_propagates() {
    assert!(validate_scheme_only("not a url").is_err());
}

#[test]
fn scheme_only_allows_arbitrary_private_ips() {
    // Documents the lenient contract: scheme-only does NOT block private ranges.
    assert!(validate_scheme_only("http://10.0.0.1:8080").is_ok());
    assert!(validate_scheme_only("https://[fe80::1]:8080").is_ok());
}

// ─── IPv4-compatible IPv6 (RFC 4291 §2.5.5.1) ────────────────────────────────
// Form `::a.b.c.d` carries an IPv4 address in the trailing 32 bits with the
// upper 96 bits all zero. `Ipv6Addr::is_loopback` matches only `::1`, so each
// of these literals would otherwise slip past the IPv6 guard and reach the
// embedded IPv4 service (cloud metadata, loopback, RFC1918).

#[test]
fn rejects_ipv4_compatible_aws_imds() {
    // ::169.254.169.254 — AWS / Azure IMDS via IPv4-compatible form.
    let err = validate_public_url("http://[::169.254.169.254]/latest/meta-data/").unwrap_err();
    assert!(matches!(err, UrlValidationError::BlockedHost(_, _)));
}

#[test]
fn rejects_ipv4_compatible_alibaba_imds() {
    // ::100.100.100.200 — Alibaba Cloud IMDS via IPv4-compatible form.
    let err = validate_public_url("http://[::100.100.100.200]/").unwrap_err();
    assert!(matches!(err, UrlValidationError::BlockedHost(_, _)));
}

#[test]
fn rejects_ipv4_compatible_loopback() {
    // ::127.0.0.1 — loopback via IPv4-compatible form (not caught by ::1 check).
    let err = validate_public_url("http://[::127.0.0.1]/").unwrap_err();
    assert!(matches!(err, UrlValidationError::BlockedHost(_, _)));
}

#[test]
fn rejects_ipv4_compatible_rfc1918() {
    // RFC1918 private ranges via IPv4-compatible form.
    assert!(validate_public_url("http://[::10.0.0.1]/").is_err());
    assert!(validate_public_url("http://[::192.168.1.1]/").is_err());
    assert!(validate_public_url("http://[::172.16.0.1]/").is_err());
}

#[test]
fn accepts_public_ipv4_compatible_not_blocked() {
    // ::1.1.1.1 — Cloudflare DNS via IPv4-compatible form. The trailing v4 is
    // publicly routable, so the URL must pass (negative case: no over-block).
    assert!(validate_public_url("http://[::1.1.1.1]/").is_ok());
}
