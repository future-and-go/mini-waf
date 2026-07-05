//! Shared SSRF-hardened HTTP client construction for outbound fetches.
//!
//! Both the remote rule-source loader and the `GeoIP` xdb updater fetch
//! operator-configured URLs from inside the WAF process, which makes them
//! SSRF targets. This module is the single place that encodes the hardened
//! posture so the two callers cannot drift:
//!
//! - The URL is validated against private / reserved / loopback / IMDS
//!   ranges before any connection is opened.
//! - The client is pinned to the IPs resolved at validation time via
//!   `resolve_to_addrs`, closing the DNS-rebinding TOCTOU window.
//! - HTTP redirects are disabled — a followed redirect escapes the pin.
//! - Connect and total timeouts plus a stable User-Agent are always set.
//!
//! Response-body size caps stay a caller concern (rules cap text in memory,
//! the xdb updater streams to a file), so they are not baked in here.

use std::time::Duration;

use anyhow::{Context, Result};

/// Stable User-Agent sent by validated outbound fetches.
pub const USER_AGENT: &str = concat!("mini-waf/", env!("CARGO_PKG_VERSION"));

/// Build an SSRF-validated, IP-pinned, redirect-disabled [`reqwest::Client`]
/// for `url`.
///
/// Validates `url` against private/reserved ranges, pins the client to the
/// addresses resolved at validation time (closing the DNS-rebinding TOCTOU
/// gap), and disables redirects (a followed redirect escapes the pin).
/// Callers must issue their requests against the same host as `url`.
pub fn build_validated_client(
    url: &str,
    connect_timeout: Duration,
    total_timeout: Duration,
    user_agent: &str,
) -> Result<reqwest::Client> {
    let (validated_url, resolved_addrs) = waf_common::url_validator::validate_public_url_with_ips(url)
        .with_context(|| format!("URL failed SSRF validation: {url}"))?;

    let mut builder = reqwest::Client::builder()
        // Disable all redirects — a redirect could point to an internal endpoint.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(total_timeout)
        .connect_timeout(connect_timeout)
        .user_agent(user_agent);

    // Pin the client to the IPs validated above.  Only applies when the URL
    // contains a DNS hostname; IP-literal URLs return an empty `resolved_addrs`.
    if !resolved_addrs.is_empty()
        && let Some(host) = validated_url.host_str()
    {
        builder = builder.resolve_to_addrs(host, &resolved_addrs);
    }

    builder.build().context("Failed to build SSRF-safe HTTP client")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(url: &str) -> Result<reqwest::Client> {
        build_validated_client(url, Duration::from_secs(5), Duration::from_secs(30), USER_AGENT)
    }

    #[test]
    fn rejects_private_range_url() {
        assert!(build("http://10.0.0.1/").is_err());
        assert!(build("http://192.168.1.1/data").is_err());
    }

    #[test]
    fn rejects_loopback_url() {
        assert!(build("http://127.0.0.1:8080/xdb").is_err());
    }

    #[test]
    fn rejects_imds_url() {
        assert!(build("http://169.254.169.254/latest/meta-data").is_err());
    }

    #[test]
    fn accepts_public_ip_literal_url() {
        // IP-literal public host: validation is deterministic (no DNS) and
        // resolved_addrs is empty, so no pin is applied.
        assert!(build("http://93.184.216.34/file.xdb").is_ok());
    }

    #[test]
    fn rejects_non_http_scheme() {
        assert!(build("file:///etc/passwd").is_err());
    }
}
