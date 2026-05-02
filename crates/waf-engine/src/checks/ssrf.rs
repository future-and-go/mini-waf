//! Server-Side Request Forgery (FR-016) — stub registered by Phase 00.
//!
//! Real detection lands in Phase 03. The stub returns `None` so the check
//! pipeline runs unchanged until then.

use waf_common::{DetectionResult, RequestCtx};

use super::Check;

/// Stub SSRF checker. Phase 03 (FR-016) replaces `check()` with the real
/// `url::Url::host_str()` parser + RFC1918 / loopback / link-local CIDR
/// match plus `ssrf_outbound_host_allowlist` bypass.
pub struct SsrfCheck;

impl SsrfCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for SsrfCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for SsrfCheck {
    fn check(&self, _ctx: &RequestCtx) -> Option<DetectionResult> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checks::scanner::ScannerCheck;
    use bytes::Bytes;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::sync::Arc;
    use waf_common::HostConfig;

    fn make_ctx() -> RequestCtx {
        RequestCtx {
            req_id: "test".to_string(),
            client_ip: "127.0.0.1".parse::<IpAddr>().unwrap(),
            client_port: 0,
            method: "GET".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::new(),
            content_length: 0,
            is_tls: false,
            host_config: Arc::new(HostConfig::default()),
            geo: None,
            tier: waf_common::tier::Tier::CatchAll,
            tier_policy: waf_common::RequestCtx::default_tier_policy(),
            cookies: HashMap::new(),
        }
    }

    #[test]
    fn stub_returns_none() {
        let checker = SsrfCheck::new();
        let ctx = make_ctx();
        assert!(checker.check(&ctx).is_none());
    }

    #[test]
    fn on_response_default_is_no_op() {
        // Stubs inherit the trait's default `on_response` no-op; this test
        // pins the contract so future overrides don't silently regress.
        let checker = SsrfCheck::new();
        let ctx = make_ctx();
        // Sanity: the *other* check we delegated default behaviour to also
        // inherits the no-op — keeps both code paths exercised.
        let scanner: Box<dyn Check> = Box::new(ScannerCheck::new());
        checker.on_response(&ctx, 200);
        scanner.on_response(&ctx, 200);
    }
}
