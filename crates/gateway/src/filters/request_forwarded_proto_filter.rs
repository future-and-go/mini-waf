//! `X-Forwarded-Proto` filter (AC-13).
//!
//! Sets `X-Forwarded-Proto` to `https` when the downstream connection was
//! TLS-terminated (`fctx.is_tls`), else `http`. Overwrites any existing
//! value so the upstream cannot be misled by a client-supplied header.

use crate::pipeline::{FilterCtx, RequestFilter};

/// Overwrite `X-Forwarded-Proto` based on downstream TLS state.
pub struct RequestForwardedProtoFilter;

impl RequestFilter for RequestForwardedProtoFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let value = if fctx.is_tls { "https" } else { "http" };
        req.insert_header("x-forwarded-proto", value)
            .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set proto", e))
    }

    fn name(&self) -> &'static str {
        "request-forwarded-proto"
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

    fn ctx_pair(is_tls: bool) -> (RequestCtx, Arc<HostConfig>) {
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
            is_tls,
            host_config: Arc::clone(&hc),
            geo: None,
        };
        (ctx, hc)
    }

    #[test]
    fn https_when_tls() {
        let (ctx, hc) = ctx_pair(true);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: true,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        RequestForwardedProtoFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("x-forwarded-proto").unwrap().as_bytes(), b"https");
    }

    #[test]
    fn http_when_plain() {
        let (ctx, hc) = ctx_pair(false);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("x-forwarded-proto", "https").expect("seed");
        RequestForwardedProtoFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("x-forwarded-proto").unwrap().as_bytes(), b"http");
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(RequestForwardedProtoFilter.name(), "request-forwarded-proto");
    }
}
