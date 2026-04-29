//! Response header blocklist filter (AC-15).
//!
//! Removes any header whose name appears in
//! `host_config.header_blocklist` (case-insensitive — HTTP header names
//! are case-insensitive per RFC 7230 §3.2). Pingora's `remove_header`
//! lowercases on lookup.

use crate::pipeline::{FilterCtx, ResponseFilter};

/// Strips configured leak-prone headers from upstream responses.
pub struct ResponseHeaderBlocklistFilter;

impl ResponseFilter for ResponseHeaderBlocklistFilter {
    fn apply(&self, resp: &mut pingora_http::ResponseHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        for name in &fctx.host_config.header_blocklist {
            let _ = resp.remove_header(&name.to_ascii_lowercase());
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "response-header-blocklist"
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

    fn make_fctx(blocklist: Vec<String>) -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig {
            header_blocklist: blocklist,
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
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
        };
        (ctx, hc)
    }

    #[test]
    fn strips_listed_headers_case_insensitive() {
        let (ctx, hc) = make_fctx(vec!["X-Powered-By-WAF".into(), "X-WAF-Version".into()]);
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        resp.insert_header("x-powered-by-waf", "1").expect("h1");
        resp.insert_header("x-waf-version", "v2").expect("h2");
        resp.insert_header("content-type", "text/plain").expect("h3");
        ResponseHeaderBlocklistFilter.apply(&mut resp, &fctx).expect("apply");
        assert!(resp.headers.get("x-powered-by-waf").is_none());
        assert!(resp.headers.get("x-waf-version").is_none());
        assert!(resp.headers.get("content-type").is_some(), "non-listed retained");
    }

    #[test]
    fn empty_blocklist_is_noop() {
        let (ctx, hc) = make_fctx(Vec::new());
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls: false,
        };
        let mut resp = ResponseHeader::build(200, None).expect("build");
        resp.insert_header("x-powered-by-waf", "1").expect("set");
        ResponseHeaderBlocklistFilter.apply(&mut resp, &fctx).expect("apply");
        assert!(resp.headers.get("x-powered-by-waf").is_some());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(ResponseHeaderBlocklistFilter.name(), "response-header-blocklist");
    }
}
