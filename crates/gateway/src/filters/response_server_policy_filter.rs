//! Server-header policy filter (AC-16).
//!
//! Thin wrapper that resolves [`ServerHeaderPolicy`] from `host_config`
//! per request and applies it.

use crate::pipeline::{FilterCtx, ResponseFilter};
use crate::policies::ServerHeaderPolicy;

pub struct ResponseServerPolicyFilter;

impl ResponseFilter for ResponseServerPolicyFilter {
    fn apply(&self, resp: &mut pingora_http::ResponseHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        ServerHeaderPolicy::from_host_config(fctx.host_config).apply(resp)
    }

    fn name(&self) -> &'static str {
        "response-server-policy"
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

    fn make_fctx(strip: bool) -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig {
            strip_server_header: strip,
            ..HostConfig::default()
        });
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

    fn fctx_for<'a>(ctx: &'a RequestCtx, hc: &'a Arc<HostConfig>) -> FilterCtx<'a> {
        FilterCtx {
            request_ctx: ctx,
            host_config: hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        }
    }

    #[test]
    fn passthrough_keeps_server_header() {
        let (ctx, hc) = make_fctx(false);
        let mut resp = ResponseHeader::build(200, None).expect("build");
        resp.insert_header("server", "nginx/1.27").expect("set");
        ResponseServerPolicyFilter.apply(&mut resp, &fctx_for(&ctx, &hc)).expect("apply");
        assert_eq!(resp.headers.get("server").unwrap().as_bytes(), b"nginx/1.27");
    }

    #[test]
    fn strip_removes_server_header() {
        let (ctx, hc) = make_fctx(true);
        let mut resp = ResponseHeader::build(200, None).expect("build");
        resp.insert_header("server", "nginx/1.27").expect("set");
        ResponseServerPolicyFilter.apply(&mut resp, &fctx_for(&ctx, &hc)).expect("apply");
        assert!(resp.headers.get("server").is_none());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(ResponseServerPolicyFilter.name(), "response-server-policy");
    }
}
