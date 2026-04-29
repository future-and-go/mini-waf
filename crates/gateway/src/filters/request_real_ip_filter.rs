//! `X-Real-IP` filter (AC-13).
//!
//! Always overwrites `X-Real-IP` with the resolved client IP from the
//! request context. Overwrite (not append) is intentional: `X-Real-IP` is
//! a single-value convention; appending would corrupt downstreams that parse
//! it as a single IP.

use crate::pipeline::{FilterCtx, RequestFilter};

/// Overwrite `X-Real-IP` with the resolved client IP.
pub struct RequestRealIpFilter;

impl RequestFilter for RequestRealIpFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let value = fctx.request_ctx.client_ip.to_string();
        req.insert_header("x-real-ip", value.as_str())
            .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set real-ip", e))
    }

    fn name(&self) -> &'static str {
        "request-real-ip"
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

    fn make_ctx(client: IpAddr) -> (RequestCtx, Arc<HostConfig>) {
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
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
        };
        (ctx, hc)
    }

    #[test]
    fn sets_real_ip() {
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (ctx, hc) = make_ctx(client);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: client,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        RequestRealIpFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("x-real-ip").unwrap().as_bytes(), b"203.0.113.9");
    }

    #[test]
    fn overwrites_existing() {
        let client = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9));
        let (ctx, hc) = make_ctx(client);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: client,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("x-real-ip", "9.9.9.9").expect("set");
        RequestRealIpFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("x-real-ip").unwrap().as_bytes(), b"203.0.113.9");
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(RequestRealIpFilter.name(), "request-real-ip");
    }
}
