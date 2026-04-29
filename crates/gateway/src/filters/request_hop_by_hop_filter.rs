//! Hop-by-hop header hygiene (RFC 7230 §6.1, AC-20).
//!
//! Strips the standard hop-by-hop headers AND any header named in the
//! request's `Connection:` token list (per-message hop-by-hop), then
//! removes `Connection` itself.
//!
//! WebSocket exception: when the handshake declares `Upgrade: websocket`,
//! both `Upgrade` and a single `Connection: upgrade` token are preserved
//! so Pingora's tunnel layer can complete the handshake.

use crate::pipeline::{FilterCtx, RequestFilter};

/// Standard hop-by-hop header set (RFC 7230 §6.1).
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip hop-by-hop headers from the upstream request.
pub struct RequestHopByHopFilter;

impl RequestFilter for RequestHopByHopFilter {
    fn apply(&self, req: &mut pingora_http::RequestHeader, _fctx: &FilterCtx<'_>) -> pingora_core::Result<()> {
        // Detect WebSocket handshake before stripping anything.
        let is_ws = req
            .headers
            .get("upgrade")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .is_some_and(|v| v.eq_ignore_ascii_case("websocket"));

        // Capture Connection-token names before we remove the header.
        let connection_tokens: Vec<String> = req
            .headers
            .get("connection")
            .and_then(|v| std::str::from_utf8(v.as_bytes()).ok())
            .map(|s| {
                s.split(',')
                    .map(|t| t.trim().to_ascii_lowercase())
                    .filter(|t| !t.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        // Strip per-Connection-token headers (skip "upgrade" if WS).
        for token in &connection_tokens {
            if is_ws && token == "upgrade" {
                continue;
            }
            req.remove_header(token.as_str());
        }

        // Strip standard hop-by-hop list.
        for name in HOP_BY_HOP {
            if is_ws && (*name == "upgrade" || *name == "connection") {
                continue;
            }
            req.remove_header(*name);
        }

        // For WS, normalise Connection to a single "upgrade" token so
        // intermediaries don't see stale extra tokens.
        if is_ws {
            req.insert_header("connection", "upgrade")
                .map_err(|e| pingora_core::Error::because(pingora_core::ErrorType::InternalError, "ws conn", e))?;
        }
        Ok(())
    }

    fn name(&self) -> &'static str {
        "request-hop-by-hop"
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
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
        };
        (ctx, hc)
    }

    fn run(req: &mut RequestHeader) {
        let (ctx, hc) = fctx();
        let f = FilterCtx {
            request_ctx: &ctx,
            host_config: &hc,
            peer_ip: ctx.client_ip,
            is_tls: false,
        };
        RequestHopByHopFilter.apply(req, &f).expect("apply");
    }

    #[test]
    fn strips_standard_hop_headers() {
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("keep-alive", "timeout=5").expect("h");
        req.insert_header("transfer-encoding", "chunked").expect("h");
        req.insert_header("te", "trailers").expect("h");
        req.insert_header("x-keep", "yes").expect("h");
        run(&mut req);
        assert!(req.headers.get("keep-alive").is_none());
        assert!(req.headers.get("transfer-encoding").is_none());
        assert!(req.headers.get("te").is_none());
        assert_eq!(req.headers.get("x-keep").unwrap().as_bytes(), b"yes");
    }

    #[test]
    fn strips_connection_named_tokens() {
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("connection", "close, X-Custom").expect("h");
        req.insert_header("x-custom", "secret").expect("h");
        req.insert_header("x-keep", "yes").expect("h");
        run(&mut req);
        assert!(req.headers.get("x-custom").is_none(), "X-Custom must be stripped");
        assert!(req.headers.get("connection").is_none());
        assert_eq!(req.headers.get("x-keep").unwrap().as_bytes(), b"yes");
    }

    #[test]
    fn preserves_upgrade_for_websocket() {
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("upgrade", "websocket").expect("h");
        req.insert_header("connection", "upgrade").expect("h");
        req.insert_header("sec-websocket-key", "abc").expect("h");
        run(&mut req);
        assert_eq!(req.headers.get("upgrade").unwrap().as_bytes(), b"websocket");
        assert_eq!(req.headers.get("connection").unwrap().as_bytes(), b"upgrade");
        assert_eq!(req.headers.get("sec-websocket-key").unwrap().as_bytes(), b"abc");
    }

    #[test]
    fn ws_strips_other_connection_tokens_but_keeps_upgrade() {
        let mut req = RequestHeader::build("GET", b"/", None).expect("build");
        req.insert_header("upgrade", "websocket").expect("h");
        req.insert_header("connection", "upgrade, x-extra").expect("h");
        req.insert_header("x-extra", "drop-me").expect("h");
        run(&mut req);
        assert!(req.headers.get("x-extra").is_none());
        assert_eq!(req.headers.get("upgrade").unwrap().as_bytes(), b"websocket");
        assert_eq!(req.headers.get("connection").unwrap().as_bytes(), b"upgrade");
    }

    #[test]
    fn name_is_stable() {
        assert_eq!(RequestHopByHopFilter.name(), "request-hop-by-hop");
    }
}
