//! `X-Forwarded-For` filter (AC-12, AC-14).
//!
//! Behaviour:
//! - If the incoming request already has `X-Forwarded-For`, append the
//!   immediate TCP peer IP (`fctx.peer_ip`). Multi-hop chains then read as
//!   `client, hop1, hop2, ...`.
//! - Otherwise, set `X-Forwarded-For` to the resolved client IP
//!   (`fctx.request_ctx.client_ip`). Resolved client respects the
//!   trusted-proxy configuration honoured by `RequestCtxBuilder`.
//!
//! Using the **resolved** client IP for the set-case (rather than the raw
//! peer) keeps spoofing protection: the builder only honours `X-Forwarded-For`
//! when the TCP peer is in the trusted-proxies list.

use crate::pipeline::{FilterCtx, RequestFilter};

/// Append-or-set `X-Forwarded-For` per RFC 7239 §5.2 conventions.
pub struct RequestXffFilter;

impl RequestFilter for RequestXffFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let existing = req
            .headers
            .get("x-forwarded-for")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .map(str::to_string);

        let new_value = existing.map_or_else(
            || fctx.request_ctx.client_ip.to_string(),
            |prev| format!("{prev}, {peer}", peer = fctx.peer_ip),
        );

        req.insert_header("x-forwarded-for", new_value.as_str())
            .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set xff", e))
    }

    fn name(&self) -> &'static str {
        "request-xff"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::FilterCtx;
    use pingora_http::RequestHeader;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use waf_common::{HostConfig, RequestCtx};

    fn fctx_with(client: IpAddr, peer: IpAddr) -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig::default());
        let ctx = RequestCtx {
            req_id: "t".into(),
            client_ip: client,
            client_port: 0,
            method: "GET".into(),
            host: "h".into(),
            port: 80,
            path: "/".into(),
            query: String::new(),
            headers: std::collections::HashMap::new(),
            body_preview: bytes::Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::clone(&hc),
            geo: None,
        };
        let _ = peer;
        (ctx, hc)
    }

    fn make_req(xff: Option<&str>) -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        if let Some(v) = xff {
            req.insert_header("x-forwarded-for", v).expect("set xff");
        }
        req
    }

    #[test]
    fn sets_when_absent() {
        let client = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (ctx, hc) = fctx_with(client, peer);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: peer,
            is_tls: false,
        };
        let mut req = make_req(None);
        RequestXffFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("x-forwarded-for").unwrap().as_bytes(), b"1.2.3.4");
    }

    #[test]
    fn appends_when_present() {
        let client = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (ctx, hc) = fctx_with(client, peer);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: peer,
            is_tls: false,
        };
        let mut req = make_req(Some("1.2.3.4"));
        RequestXffFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(
            req.headers.get("x-forwarded-for").unwrap().as_bytes(),
            b"1.2.3.4, 10.0.0.1"
        );
    }

    #[test]
    fn appends_multi_hop_chain() {
        let client = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));
        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        let (ctx, hc) = fctx_with(client, peer);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: peer,
            is_tls: false,
        };
        let mut req = make_req(Some("1.2.3.4, 10.0.0.1"));
        RequestXffFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(
            req.headers.get("x-forwarded-for").unwrap().as_bytes(),
            b"1.2.3.4, 10.0.0.1, 10.0.0.5"
        );
    }
}
