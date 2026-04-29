//! `RequestFilter` adapter for the [`HostHeaderPolicy`] strategy (AC-25).
//!
//! The strategy itself lives in `policies/host_header_policy.rs` so it can
//! be unit-tested without the filter trait. Built per-request from
//! `fctx.host_config.preserve_host` so config changes take effect on the
//! next request without rebuilding the chain.

use crate::pipeline::{FilterCtx, RequestFilter};
use crate::policies::HostHeaderPolicy;

/// Filter wrapper around [`HostHeaderPolicy`].
pub struct RequestHostPolicyFilter;

impl RequestFilter for RequestHostPolicyFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        let policy = HostHeaderPolicy::from_host_config(fctx.host_config);
        policy.apply(req)
    }

    fn name(&self) -> &'static str {
        "request-host-policy"
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

    fn make_fctx(preserve: bool, remote_host: &str) -> (RequestCtx, Arc<HostConfig>) {
        let hc = Arc::new(HostConfig {
            preserve_host: preserve,
            remote_host: remote_host.into(),
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
    fn preserve_keeps_original_host() {
        let (ctx, hc) = make_fctx(true, "backend.internal");
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("host", "client.example.com").expect("set");
        RequestHostPolicyFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("host").unwrap().as_bytes(), b"client.example.com");
    }

    #[test]
    fn rewrite_replaces_host_with_remote() {
        let (ctx, hc) = make_fctx(false, "backend.internal");
        let fctx = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("host", "client.example.com").expect("set");
        RequestHostPolicyFilter.apply(&mut req, &fctx).expect("apply");
        assert_eq!(req.headers.get("host").unwrap().as_bytes(), b"backend.internal");
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(RequestHostPolicyFilter.name(), "request-host-policy");
    }
}
