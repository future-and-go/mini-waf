//! Builder for [`RequestCtx`] from a Pingora [`Session`].
//!
//! Centralises all context construction so `is_tls` is always derived from
//! `session.digest().ssl_digest` rather than hardcoded.  A pure inner
//! function `build_from_parts` is unit-testable without a live Pingora session.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use bytes::Bytes;
use pingora_proxy::Session;
use uuid::Uuid;
use waf_common::{HostConfig, RequestCtx};

/// Builds a [`RequestCtx`] from a Pingora session and optional host config.
pub struct RequestCtxBuilder<'a> {
    session: &'a Session,
    host_config: Option<Arc<HostConfig>>,
    trust_proxy_headers: bool,
    trusted_proxies: &'a [ipnet::IpNet],
}

impl<'a> RequestCtxBuilder<'a> {
    /// Create a new builder.
    ///
    /// `trust_proxy_headers` and `trusted_proxies` control whether
    /// `X-Forwarded-For` is honoured for client IP resolution.
    pub const fn new(session: &'a Session, trust_proxy_headers: bool, trusted_proxies: &'a [ipnet::IpNet]) -> Self {
        Self {
            session,
            host_config: None,
            trust_proxy_headers,
            trusted_proxies,
        }
    }

    /// Attach the resolved [`HostConfig`] for this request.
    #[must_use]
    pub fn with_host_config(mut self, hc: Arc<HostConfig>) -> Self {
        self.host_config = Some(hc);
        self
    }

    /// Consume the builder and produce a [`RequestCtx`].
    ///
    /// # Panics
    /// Never — all fields have safe defaults.
    pub fn build(self) -> RequestCtx {
        // Detect TLS from the downstream connection digest — fixes the
        // hardcoded `is_tls: false` that existed in the old proxy.rs.
        let is_tls = self.session.digest().and_then(|d| d.ssl_digest.as_ref()).is_some();

        let peer_addr: SocketAddr = self
            .session
            .client_addr()
            .and_then(|a| a.as_inet())
            .copied()
            .unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));

        let client_ip = extract_client_ip_from_session(
            self.session,
            peer_addr.ip(),
            self.trust_proxy_headers,
            self.trusted_proxies,
        );

        let host_config = self.host_config.unwrap_or_default();

        // Collect headers into a lowercase HashMap — do NOT log values.
        let mut headers = HashMap::new();
        for (name, value) in &self.session.req_header().headers {
            if let Ok(v) = std::str::from_utf8(value.as_bytes()) {
                headers.insert(name.as_str().to_lowercase(), v.to_string());
            }
        }

        let uri = self.session.req_header().uri.clone();
        let content_length = headers
            .get("content-length")
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);

        build_from_parts(
            client_ip,
            peer_addr.port(),
            self.session.req_header().method.to_string(),
            uri.path().to_string(),
            uri.query().unwrap_or("").to_string(),
            headers,
            content_length,
            is_tls,
            host_config,
        )
    }
}

/// Pure function that assembles a [`RequestCtx`] from already-extracted parts.
///
/// Extracted to enable unit testing without a live Pingora session.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub fn build_from_parts(
    client_ip: IpAddr,
    client_port: u16,
    method: String,
    path: String,
    query: String,
    headers: HashMap<String, String>,
    content_length: u64,
    is_tls: bool,
    host_config: Arc<HostConfig>,
) -> RequestCtx {
    RequestCtx {
        req_id: Uuid::new_v4().to_string(),
        client_ip,
        client_port,
        method,
        host: host_config.host.clone(),
        port: host_config.port,
        path,
        query,
        headers,
        body_preview: Bytes::new(),
        content_length,
        is_tls,
        host_config,
        geo: None,
    }
}

/// Resolve the effective client IP from session state.
///
/// Honours `X-Forwarded-For` only when `trust_proxy_headers` is `true` **and**
/// the TCP peer falls within `trusted_proxies` (or the list is empty, which
/// means "trust any peer" for backwards compatibility).
fn extract_client_ip_from_session(
    session: &Session,
    peer_ip: IpAddr,
    trust_proxy_headers: bool,
    trusted_proxies: &[ipnet::IpNet],
) -> IpAddr {
    if trust_proxy_headers {
        let peer_trusted = trusted_proxies.is_empty() || trusted_proxies.iter().any(|net| net.contains(&peer_ip));

        if peer_trusted
            && let Some(xff) = session.get_header("x-forwarded-for")
            && let Ok(s) = std::str::from_utf8(xff.as_bytes())
            && let Some(first) = s.split(',').next()
            && let Ok(ip) = first.trim().parse()
        {
            return ip;
        }
    }
    peer_ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_host_config(host: &str, port: u16, ssl: bool) -> Arc<HostConfig> {
        Arc::new(HostConfig {
            host: host.to_string(),
            port,
            ssl,
            ..HostConfig::default()
        })
    }

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn test_tls_on() {
        let hc = make_host_config("example.com", 443, true);
        let ctx = build_from_parts(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            12345,
            "GET".into(),
            "/".into(),
            String::new(),
            make_headers(&[]),
            0,
            true, // is_tls
            hc,
        );
        assert!(ctx.is_tls, "expected is_tls = true");
        assert_eq!(ctx.host, "example.com");
        assert_eq!(ctx.port, 443);
    }

    #[test]
    fn test_tls_off() {
        let hc = make_host_config("example.com", 80, false);
        let ctx = build_from_parts(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            54321,
            "POST".into(),
            "/api".into(),
            "foo=bar".into(),
            make_headers(&[("content-length", "5")]),
            5,
            false, // is_tls
            hc,
        );
        assert!(!ctx.is_tls, "expected is_tls = false");
        assert_eq!(ctx.content_length, 5);
        assert_eq!(ctx.query, "foo=bar");
    }

    #[test]
    fn test_missing_host_header_uses_host_config() {
        let hc = make_host_config("fallback.example.com", 8080, false);
        let ctx = build_from_parts(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            "GET".into(),
            "/health".into(),
            String::new(),
            make_headers(&[]), // no host header
            0,
            false,
            hc,
        );
        // host comes from HostConfig.host, not from a header
        assert_eq!(ctx.host, "fallback.example.com");
        assert_eq!(ctx.port, 8080);
    }

    #[test]
    fn test_ipv4_peer() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        let hc = make_host_config("site.com", 80, false);
        let ctx = build_from_parts(
            ip,
            9999,
            "GET".into(),
            "/".into(),
            String::new(),
            make_headers(&[]),
            0,
            false,
            hc,
        );
        assert_eq!(ctx.client_ip, ip);
        assert_eq!(ctx.client_port, 9999);
    }

    #[test]
    fn test_ipv6_peer() {
        let ip = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let hc = make_host_config("v6site.com", 443, true);
        let ctx = build_from_parts(
            ip,
            1234,
            "GET".into(),
            "/v6".into(),
            String::new(),
            make_headers(&[]),
            0,
            true,
            hc,
        );
        assert_eq!(ctx.client_ip, ip);
        assert!(ctx.is_tls);
    }

    #[test]
    fn test_req_id_is_unique() {
        let hc = make_host_config("a.com", 80, false);
        let hc2 = make_host_config("b.com", 80, false);
        let ctx1 = build_from_parts(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            "GET".into(),
            "/".into(),
            String::new(),
            make_headers(&[]),
            0,
            false,
            hc,
        );
        let ctx2 = build_from_parts(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            0,
            "GET".into(),
            "/".into(),
            String::new(),
            make_headers(&[]),
            0,
            false,
            hc2,
        );
        assert_ne!(ctx1.req_id, ctx2.req_id, "req_id must be unique per request");
    }
}
