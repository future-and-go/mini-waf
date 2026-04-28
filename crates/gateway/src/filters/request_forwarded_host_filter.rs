//! `X-Forwarded-Host` filter (AC-13).
//!
//! Copies the original client `Host` header into `X-Forwarded-Host` so the
//! upstream can recover the user-facing hostname even when host-rewrite
//! mode changes the request `Host`.
//!
//! Order requirement: this filter MUST run BEFORE the host-policy filter
//! so it captures the original `Host` rather than the rewritten value
//! (encoded in chain registration in `WafProxy::new`).
//!
//! No-op if the request has no `Host` header (HTTP/1.0 or malformed).

use crate::pipeline::{FilterCtx, RequestFilter};

/// Copy original `Host` to `X-Forwarded-Host`.
pub struct RequestForwardedHostFilter;

impl RequestFilter for RequestForwardedHostFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, _fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let original = req
            .headers
            .get("host")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .map(str::to_string);
        if let Some(host) = original {
            req.insert_header("x-forwarded-host", host.as_str())
                .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set fwd-host", e))?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "request-forwarded-host"
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

    fn fctx() -> (RequestCtx, Arc<HostConfig>) {
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
    fn copies_host_header() {
        let (ctx, hc) = fctx();
        let f = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("host", "client.example.com").expect("set host");
        RequestForwardedHostFilter.apply(&mut req, &f).expect("apply");
        assert_eq!(
            req.headers.get("x-forwarded-host").unwrap().as_bytes(),
            b"client.example.com"
        );
    }

    #[test]
    fn no_op_when_host_missing() {
        let (ctx, hc) = fctx();
        let f = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        RequestForwardedHostFilter.apply(&mut req, &f).expect("apply");
        assert!(req.headers.get("x-forwarded-host").is_none());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(RequestForwardedHostFilter.name(), "request-forwarded-host");
    }
}
