//! Contract tests for the outbound-URL SSRF validator the engine relies on
//! for webhook/remote-rule fetches: scheme allow-list, private/reserved IP
//! blocking (IPv4 and IPv6), forbidden hostname literals, and fail-closed
//! DNS behavior.
//!
//! Only deterministic paths are exercised — IP literals, blocked hostnames,
//! and the reserved `.invalid` TLD — so no test depends on live DNS answers.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use waf_common::url_validator::{
    UrlValidationError, validate_public_url, validate_public_url_with_ips, validate_scheme_only,
};

// ── Scheme allow-list ──────────────────────────────────────────────────────────

#[test]
fn non_http_schemes_are_rejected_by_both_levels() {
    for raw in ["ftp://example.com/", "file:///etc/passwd", "gopher://example.com/"] {
        assert!(
            matches!(validate_public_url(raw), Err(UrlValidationError::DisallowedScheme(_))),
            "public validation must reject {raw}"
        );
        assert!(
            matches!(validate_scheme_only(raw), Err(UrlValidationError::DisallowedScheme(_))),
            "scheme-only validation must reject {raw}"
        );
    }
}

#[test]
fn scheme_error_names_the_offending_scheme() {
    let err = validate_public_url("gopher://example.com/").unwrap_err();
    assert!(err.to_string().contains("gopher"));
}

#[test]
fn unparseable_input_is_a_parse_error() {
    assert!(matches!(
        validate_public_url("not a url at all"),
        Err(UrlValidationError::Parse(_))
    ));
}

// ── IPv4 literal ranges ────────────────────────────────────────────────────────

#[test]
fn private_and_reserved_ipv4_literals_are_blocked() {
    for ip in [
        "127.0.0.1",       // loopback
        "10.0.0.1",        // RFC 1918
        "172.16.0.1",      // RFC 1918
        "192.168.1.1",     // RFC 1918
        "169.254.169.254", // link-local / cloud IMDS
        "0.0.0.0",         // unspecified
        "255.255.255.255", // broadcast
        "224.0.0.1",       // multicast
        "100.64.0.1",      // CGNAT low edge
        "100.127.255.254", // CGNAT high edge
    ] {
        let raw = format!("http://{ip}/hook");
        assert!(
            matches!(validate_public_url(&raw), Err(UrlValidationError::BlockedHost(host, _)) if host == ip),
            "{ip} must be blocked"
        );
    }
}

#[test]
fn public_ipv4_literals_pass_with_no_dns_pinning_needed() {
    // Neighbours of the CGNAT block (100.64.0.0/10) prove the mask is exact.
    for ip in ["1.1.1.1", "93.184.216.34", "100.63.255.254", "100.128.0.1"] {
        let raw = format!("https://{ip}:8443/hook");
        let (url, resolved) = validate_public_url_with_ips(&raw).unwrap_or_else(|e| panic!("{ip} should pass: {e}"));
        assert_eq!(url.host_str(), Some(ip));
        assert!(resolved.is_empty(), "IP literals need no resolved-address pinning");
    }
}

// ── IPv6 literal ranges ────────────────────────────────────────────────────────

#[test]
fn private_and_reserved_ipv6_literals_are_blocked() {
    for ip in [
        "::1",             // loopback
        "::",              // unspecified
        "ff02::1",         // multicast
        "fc00::1",         // ULA fc00::/7
        "fd12:3456::1",    // ULA upper half
        "fe80::1",         // link-local
        "::ffff:10.0.0.1", // IPv4-mapped private
        "2001:db8::1",     // documentation
        "64:ff9b::7f00:1", // NAT64 translation prefix
    ] {
        let raw = format!("http://[{ip}]/hook");
        assert!(
            matches!(validate_public_url(&raw), Err(UrlValidationError::BlockedHost(_, _))),
            "{ip} must be blocked"
        );
    }
}

#[test]
fn public_ipv6_literal_passes() {
    let (url, resolved) = validate_public_url_with_ips("https://[2001:4860:4860::8888]/hook").expect("public IPv6");
    assert_eq!(url.host_str(), Some("[2001:4860:4860::8888]"));
    assert!(resolved.is_empty());
}

// ── Forbidden hostname literals ────────────────────────────────────────────────

#[test]
fn dangerous_hostname_literals_are_blocked_case_insensitively() {
    for host in [
        "localhost",
        "LOCALHOST",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "broadcasthost",
        "metadata.google.internal",
        "Metadata.Google.Internal",
    ] {
        let raw = format!("http://{host}/hook");
        assert!(
            matches!(
                validate_public_url(&raw),
                Err(UrlValidationError::BlockedHost(_, reason)) if reason.contains("explicitly blocked")
            ),
            "{host} must be blocked by the hostname list"
        );
    }
}

#[test]
fn blocked_host_error_names_the_host() {
    let err = validate_public_url("http://localhost/hook").unwrap_err();
    assert!(err.to_string().contains("localhost"));
}

// ── Fail-closed DNS behavior ───────────────────────────────────────────────────

#[test]
fn unresolvable_hostname_fails_closed() {
    // `.invalid` is reserved (RFC 6761): resolvers must return NXDOMAIN,
    // so this is deterministic without network access.
    let err = validate_public_url("https://definitely-not-real.invalid/hook").unwrap_err();
    assert!(
        matches!(&err, UrlValidationError::BlockedHost(host, reason)
            if host == "definitely-not-real.invalid" && reason.contains("could not be resolved")),
        "unexpected error: {err}"
    );
}

// ── Lenient scheme-only level ──────────────────────────────────────────────────

#[test]
fn scheme_only_validation_permits_loopback_and_private_hosts() {
    for raw in [
        "http://127.0.0.1:8080",
        "http://localhost:8080/v1",
        "http://10.0.0.5/lapi",
        "http://[::1]:8080",
    ] {
        let url = validate_scheme_only(raw).unwrap_or_else(|e| panic!("{raw} should pass scheme-only: {e}"));
        assert!(matches!(url.scheme(), "http" | "https"));
    }
}
