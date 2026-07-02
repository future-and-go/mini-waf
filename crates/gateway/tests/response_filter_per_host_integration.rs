//! US-1801 Phase 4 — prove the response filter chain honors a `HostConfig`
//! built from a per-host `HostResponseFilter` override (the admin-API / boot
//! path: `HostConfig::default()` + `apply_response_filter`).
//!
//! A host *with* an override has its blocklisted header stripped, its `Server`
//! header scrubbed, and an `internal_patterns` match masked in the body. A host
//! *without* an override keeps the default behavior (header preserved).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use bytes::Bytes;
use gateway::context::BodyMaskState;
use gateway::filters::{
    CompiledMask, ResponseHeaderBlocklistFilter, ResponseServerPolicyFilter, apply_body_mask_chunk,
};
use gateway::pipeline::{FilterCtx, ResponseFilter};
use pingora_http::ResponseHeader;
use waf_common::{HostConfig, HostResponseFilter, RequestCtx};

fn request_ctx(hc: &Arc<HostConfig>) -> RequestCtx {
    RequestCtx {
        req_id: "t".into(),
        client_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        peer_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
        client_port: 0,
        method: "GET".into(),
        host: "h".into(),
        port: 80,
        path: "/".into(),
        query: String::new(),
        headers: HashMap::new(),
        body_preview: Bytes::new(),
        content_length: 0,
        is_tls: false,
        host_config: Arc::clone(hc),
        geo: None,
        tier: waf_common::tier::Tier::CatchAll,
        tier_policy: RequestCtx::default_tier_policy(),
        cookies: HashMap::new(),
        device_fp: None,
        tx_velocity_token: None,
    }
}

fn host_with_override() -> Arc<HostConfig> {
    let mut hc = HostConfig::default();
    hc.apply_response_filter(&HostResponseFilter {
        body_scan_enabled: false,
        body_scan_max_body_bytes: 65536,
        internal_patterns: vec![r"10\.0\.0\.\d+".to_string()],
        header_blocklist: vec!["X-Powered-By".to_string()],
        strip_server_header: true,
    });
    Arc::new(hc)
}

#[test]
fn per_host_override_strips_headers() {
    let hc = host_with_override();
    let ctx = request_ctx(&hc);
    let fctx = FilterCtx {
        request_ctx: &ctx,
        host_config: &hc,
        peer_ip: ctx.client_ip,
        is_tls: false,
    };

    let mut resp = ResponseHeader::build(200, None).unwrap();
    resp.insert_header("server", "nginx/1.27").unwrap();
    resp.insert_header("x-powered-by", "PHP/8.2").unwrap();
    resp.insert_header("content-type", "text/plain").unwrap();

    ResponseHeaderBlocklistFilter.apply(&mut resp, &fctx).unwrap();
    ResponseServerPolicyFilter.apply(&mut resp, &fctx).unwrap();

    assert!(
        resp.headers.get("x-powered-by").is_none(),
        "blocklisted header stripped"
    );
    assert!(resp.headers.get("server").is_none(), "Server header scrubbed");
    assert!(resp.headers.get("content-type").is_some(), "unrelated header kept");
}

#[test]
fn per_host_override_masks_internal_pattern_in_body() {
    let hc = host_with_override();
    let mask = Arc::new(CompiledMask::build(
        &hc.internal_patterns,
        &hc.mask_token,
        hc.body_mask_max_bytes,
    ));
    assert!(!mask.is_noop(), "internal_patterns must compile to an active masker");

    let mut state = BodyMaskState {
        enabled: true,
        ..Default::default()
    };
    let mut body: Option<Bytes> = Some(Bytes::from_static(b"upstream leaked 10.0.0.5 in the body"));
    apply_body_mask_chunk(&mut state, &mask, &mut body, true);

    let out = body.expect("masked body emitted");
    assert!(!out.windows(8).any(|w| w == b"10.0.0.5"), "internal IP must be masked");
    assert!(out.windows(10).any(|w| w == b"[redacted]"), "mask token present");
}

#[test]
fn host_without_override_keeps_headers() {
    // Default HostConfig has an empty server-strip and a default header_blocklist
    // that does NOT include X-Powered-By.
    let hc = Arc::new(HostConfig::default());
    let ctx = request_ctx(&hc);
    let fctx = FilterCtx {
        request_ctx: &ctx,
        host_config: &hc,
        peer_ip: ctx.client_ip,
        is_tls: false,
    };

    let mut resp = ResponseHeader::build(200, None).unwrap();
    resp.insert_header("server", "nginx/1.27").unwrap();
    resp.insert_header("x-powered-by", "PHP/8.2").unwrap();

    ResponseHeaderBlocklistFilter.apply(&mut resp, &fctx).unwrap();
    ResponseServerPolicyFilter.apply(&mut resp, &fctx).unwrap();

    assert!(resp.headers.get("x-powered-by").is_some(), "no override → header kept");
    assert!(resp.headers.get("server").is_some(), "no override → Server kept");
}
