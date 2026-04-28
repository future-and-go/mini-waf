//! Response `Via` strip filter (AC-15).
//!
//! Unconditionally removes the `Via` response header so the proxy chain
//! does not leak hop topology to downstream clients. RFC 7230 §5.7.1
//! permits intermediaries to omit `Via`; we choose to always strip.

use crate::pipeline::{FilterCtx, ResponseFilter};

/// Strips the `Via` header from upstream responses.
pub struct ResponseViaStripFilter;

impl ResponseFilter for ResponseViaStripFilter {
    fn apply(&self, resp: &mut pingora_http::ResponseHeader, _fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let _ = resp.remove_header("via");
        Ok(())
    }

    fn name(&self) -> &'static str {
        "response-via-strip"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::FilterCtx;
    use pingora_http::ResponseHeader;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use waf_common::{HostConfig, RequestCtx};

    fn make_fctx() -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig::default());
        let ctx = RequestCtx {
            req_id: "t".into(),
            client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
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
        (ctx, hc)
    }

    #[test]
    fn strips_via_when_present() {
        let (ctx, hc) = make_fctx();
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        resp.insert_header("via", "1.1 proxy.internal").expect("set via");
        ResponseViaStripFilter.apply(&mut resp, &fctx).expect("apply");
        assert!(resp.headers.get("via").is_none(), "via must be removed");
    }

    #[test]
    fn noop_when_absent() {
        let (ctx, hc) = make_fctx();
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        ResponseViaStripFilter.apply(&mut resp, &fctx).expect("apply");
        assert!(resp.headers.get("via").is_none());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(ResponseViaStripFilter.name(), "response-via-strip");
    }
}
