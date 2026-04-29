//! Response `Location` rewrite filter (AC-18).
//!
//! Builds a [`LocationRewritePolicy`] per request from `fctx.host_config`
//! and rewrites the `Location` header when it points at the internal backend.

use crate::pipeline::{FilterCtx, ResponseFilter};
use crate::policies::LocationRewritePolicy;

pub struct ResponseLocationRewriter;

impl ResponseFilter for ResponseLocationRewriter {
    fn apply(&self, resp: &mut pingora_http::ResponseHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let Some(value) = resp
            .headers
            .get("location")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .map(str::to_string)
        else {
            return Ok(());
        };
        let policy = LocationRewritePolicy::from_host_config(fctx.host_config, fctx.is_tls);
        if let Some(new_value) = policy.rewrite(&value) {
            resp.insert_header("location", new_value.as_str())
                .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "set location", e))?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "response-location-rewrite"
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

    fn fctx(is_tls: bool) -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig {
            host: "public.example.com".into(),
            remote_host: "backend".into(),
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
            is_tls,
            host_config: Arc::clone(&hc),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: std::collections::HashMap::new(),
        };
        (ctx, hc)
    }

    fn run(is_tls: bool, location: Option<&str>) -> ResponseHeader {
        let (ctx, hc) = fctx(is_tls);
        let f = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            is_tls,
        };
        let mut resp = ResponseHeader::build(302, None).expect("build");
        if let Some(loc) = location {
            resp.insert_header("location", loc).expect("set");
        }
        ResponseLocationRewriter.apply(&mut resp, &f).expect("apply");
        resp
    }

    #[test]
    fn rewrites_internal_to_public_https() {
        let resp = run(true, Some("http://backend:8080/x"));
        assert_eq!(
            resp.headers.get("location").unwrap().as_bytes(),
            b"https://public.example.com/x"
        );
    }

    #[test]
    fn rewrites_internal_to_public_http_when_no_tls() {
        let resp = run(false, Some("http://backend:8080/x"));
        assert_eq!(
            resp.headers.get("location").unwrap().as_bytes(),
            b"http://public.example.com/x"
        );
    }

    #[test]
    fn relative_passthrough() {
        let resp = run(true, Some("/x"));
        assert_eq!(resp.headers.get("location").unwrap().as_bytes(), b"/x");
    }

    #[test]
    fn no_location_is_noop() {
        let resp = run(true, None);
        assert!(resp.headers.get("location").is_none());
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(ResponseLocationRewriter.name(), "response-location-rewrite");
    }
}
