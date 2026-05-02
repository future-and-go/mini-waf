//! Oversized / deeply-nested body abuse (FR-020) — stub registered by Phase 00.
//!
//! Real detection lands in Phase 06. The stub returns `None` so the check
//! pipeline runs unchanged until then.

use waf_common::{DetectionResult, RequestCtx};

use super::Check;

/// Stub body-abuse checker.
///
/// Phase 06 (FR-020) replaces `check()` with a size gate
/// (`max_body_size`, default 64 KiB to match the gateway preview limit), an
/// iterative JSON walker enforcing `max_json_depth` / `max_json_keys`, and
/// invalid-UTF-8 / control-char rejection.
pub struct RequestBodyAbuseCheck;

impl RequestBodyAbuseCheck {
    pub const fn new() -> Self {
        Self
    }
}

impl Default for RequestBodyAbuseCheck {
    fn default() -> Self {
        Self::new()
    }
}

impl Check for RequestBodyAbuseCheck {
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
            method: "POST".to_string(),
            host: "example.com".to_string(),
            port: 80,
            path: "/api/upload".to_string(),
            query: String::new(),
            headers: HashMap::new(),
            body_preview: Bytes::from_static(br#"{"x":1}"#),
            content_length: 7,
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
        let checker = RequestBodyAbuseCheck::new();
        let ctx = make_ctx();
        assert!(checker.check(&ctx).is_none());
    }
}
