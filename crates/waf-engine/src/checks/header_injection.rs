//! HTTP header injection / smuggling (FR-017) — stub registered by Phase 00.
//!
//! Real detection lands in Phase 04. The stub returns `None` so the check
//! pipeline runs unchanged until then.

use waf_common::{DetectionResult, RequestCtx};

use super::Check;

/// Stub header-injection checker.
///
/// Phase 04 (FR-017) replaces `check()` with CRLF / NUL-byte detection in
/// header values, X-Forwarded-For hop-count validation against
/// `xf2_max_hops`, and `Host` header validation against
/// `host_inbound_whitelist`.
pub struct HeaderInjectionCheck;

impl HeaderInjectionCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for HeaderInjectionCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for HeaderInjectionCheck {
    fn check(&self, _ctx: &RequestCtx) -> Option<DetectionResult> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let checker = HeaderInjectionCheck::new();
        let ctx = make_ctx();
        assert!(checker.check(&ctx).is_none());
    }
}
